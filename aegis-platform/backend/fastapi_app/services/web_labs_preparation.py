"""Read-only lab metadata preview; never an execution or authorization grant."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.utils import timezone
from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from fastapi_app.core.dependencies import project_access_q
from django_project.system.credential_models import CredentialSecret
from enterprise.models import OrganizationMembership, TenantProject
from enterprise.provider_approval_models import ProviderApprovalDecision
from enterprise.web_security_models import ProviderApprovalRecord

from .authorization_guard import asset_target, current_asset_authorization
from .burp_mcp_gateway import BURP_MCP_CAPABILITY_ID, _OPERATION_ARGUMENTS, _TOOL_RE, _endpoint, BurpMCPProviderError, validate_transport_manifest
from .capability_registry import CAPABILITIES
from .credential_execution import _canonical_web_origin, normalize_credential_refs
from .provider_approval import evaluate_provider_admissibility
from .wstg_catalog import WSTGCatalog


CONTRACT_VERSION = 'aegis.web-labs-readiness.v1'
DEFINITION_PATH = Path(__file__).resolve().parents[2] / 'resources/web-labs/bac-orders-v1.json'


class WebLabsAccessError(ValueError):
    """Unavailable and inaccessible references deliberately share one error."""


class UnknownLabDefinition(ValueError):
    pass


def _accessible_scope(*, actor_id: str, project_id: str, asset_id: str):
    actor = get_user_model().objects.filter(pk=actor_id, is_active=True).first()
    project = Project.objects.filter(pk=project_id, status=Project.Status.ACTIVE).first()
    if (not actor or not project or not Project.objects.filter(pk=project.pk)
            .filter(project_access_q(actor_id)).exists()):
        raise WebLabsAccessError('المشروع أو الأصل غير متاح ضمن وصولك الحالي.')
    asset = Asset.objects.filter(
        pk=asset_id, project_id=project_id, is_active=True
    ).first()
    if not asset:
        raise WebLabsAccessError('المشروع أو الأصل غير متاح ضمن وصولك الحالي.')
    return actor, project, asset


def lab_definition(identifier: str) -> dict[str, Any]:
    definition = json.loads(DEFINITION_PATH.read_text(encoding='utf-8'))
    if identifier != definition['id']:
        raise UnknownLabDefinition('تعريف المختبر غير معروف؛ اختر تعريفًا مثبتًا في النظام.')
    return definition


def _web_target(asset: Asset) -> str:
    target = asset_target(asset)
    try:
        parsed = urlsplit(target)
        if (asset.type not in {Asset.Type.WEBSITE, Asset.Type.API_ENDPOINT}
                or parsed.scheme not in {'http', 'https'} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or any(c.isspace() or ord(c) < 32 for c in target)):
            return ''
        _ = parsed.port
    except ValueError:
        return ''
    return target


def _provider_metadata(project_id: str) -> tuple[dict[str, Any], list[str]]:
    # One latest decision per provider, including revocation; never search back for a grant.
    candidates = list(ProviderApprovalDecision.objects.filter(
        project_id=project_id, capability=BURP_MCP_CAPABILITY_ID,
    ).order_by('provider_name', '-decision_version', '-created_at', '-id').distinct('provider_name')[:2])
    if len(candidates) != 1:
        return {'state': 'missing' if not candidates else 'ambiguous', 'decision_ref': None}, []
    decision = candidates[0]
    record = ProviderApprovalRecord.objects.filter(
        project_id=project_id, provider_name=decision.provider_name,
        provider_version=decision.provider_version, capability=BURP_MCP_CAPABILITY_ID,
    ).order_by('-created_at', '-id').first()
    gate = evaluate_provider_admissibility(
        project_id=project_id, provider_name=decision.provider_name,
        provider_version=decision.provider_version, capability=BURP_MCP_CAPABILITY_ID,
        expected_decision_id=str(decision.id),
        expected_legacy_approval_id=str(record.id) if record else None,
    )
    metadata = {'state': 'inadmissible', 'decision_ref': str(decision.id)}
    if not record or not gate['allowed']:
        return metadata, []
    manifest = decision.manifest if isinstance(decision.manifest, dict) else {}
    mapping = manifest.get('mcp_tools')
    if (not isinstance(mapping, dict) or not mapping
            or any(op not in _OPERATION_ARGUMENTS or not isinstance(tool, str)
                   or not _TOOL_RE.fullmatch(tool)
                   or (op == 'burp.http_request' and tool != 'send_http1_request') for op, tool in mapping.items())):
        metadata['state'] = 'invalid_tool_mapping'
        return metadata, []
    try:
        validate_transport_manifest(manifest, mapping)
    except (BurpMCPProviderError, ValueError):
        metadata['state'] = 'invalid_transport'
        return metadata, []
    try:
        _endpoint(manifest)  # Syntax/policy only; no request or DNS lookup.
    except (BurpMCPProviderError, ValueError):
        metadata['state'] = 'invalid_endpoint'
        return metadata, []
    metadata['state'] = 'metadata_ready'
    return metadata, sorted(mapping)


def _credential_metadata(project_id: str, refs: list[str], target: str,
                         identities: list[str]) -> tuple[list[dict[str, Any]], bool]:
    # Explicit projection excludes ciphertext, fingerprints and arbitrary scope from output.
    rows = {str(row['id']): row for row in CredentialSecret.objects.filter(
        project_id=project_id, id__in=refs,
    ).values('id', 'kind', 'status', 'scope', 'version')}
    result, bound = [], []
    for ref in refs:
        row = rows.get(ref)
        state, identity = 'unavailable', None
        if row:
            scope = row['scope'] if isinstance(row['scope'], dict) else {}
            identity = scope.get('browser_identity_ref')
            if identity not in identities:
                identity = None
            state = 'invalid_binding'
            if row['status'] != CredentialSecret.Status.ACTIVE:
                state = 'revoked'
            elif row['kind'] not in {CredentialSecret.Kind.TOKEN, CredentialSecret.Kind.GENERIC}:
                state = 'unsupported_kind'
            else:
                try:
                    same_origin = bool(target) and _canonical_web_origin(
                        scope.get('browser_origin', '')
                    ) == _canonical_web_origin(target)
                except (ValueError, TypeError):
                    same_origin = False
                if same_origin and identity:
                    state = 'metadata_ready'
                    bound.append(identity)
        result.append({'credential_ref': ref, 'identity_ref': identity,
                       'state': state, 'version': row['version'] if row else None,
                       'message_ar': {
                           'unavailable': 'المرجع غير متاح في المشروع؛ لا نكشف وجوده في مشروع آخر.',
                           'revoked': 'مرجع الهوية ملغى ولا يصلح للاستخدام.',
                           'unsupported_kind': 'نوع المرجع لا يلائم هوية هذا المختبر.',
                           'invalid_binding': 'ربط الهوية أو نطاق العنوان لا يطابق تعريف المختبر والأصل.',
                           'metadata_ready': 'بيانات المرجع مناسبة؛ السر وصلاحية الجلسة لم يُفحصا.',
                       }[state]})
    ready = (sorted(bound) == sorted(identities)
             and all(item['state'] == 'metadata_ready' for item in result))
    return result, ready


def list_web_lab_credential_options(*, actor_id: str, project_id: str, asset_id: str,
                                    lab_definition_id: str) -> dict[str, Any]:
    """Return only safe project-scoped metadata for credentials usable by this lab."""
    _actor, _project, asset = _accessible_scope(
        actor_id=actor_id, project_id=project_id, asset_id=asset_id
    )
    tenant = TenantProject.objects.filter(
        project_id=project_id, organization__is_active=True
    ).first()
    tenant_ready = bool(
        tenant
        and OrganizationMembership.objects.filter(
            organization_id=tenant.organization_id,
            user_id=actor_id,
            is_active=True,
        ).exists()
    )
    if not tenant_ready:
        raise WebLabsAccessError('المشروع أو الأصل غير متاح ضمن وصولك الحالي.')
    definition = lab_definition(lab_definition_id)
    target = _web_target(asset)
    identities = set(definition['identity_refs'])
    options: list[dict[str, Any]] = []
    rows = CredentialSecret.objects.filter(
        project_id=project_id,
        status=CredentialSecret.Status.ACTIVE,
        kind__in=[CredentialSecret.Kind.TOKEN, CredentialSecret.Kind.GENERIC],
    ).values('id', 'name', 'kind', 'scope', 'version')
    for row in rows:
        scope = row['scope'] if isinstance(row['scope'], dict) else {}
        identity = scope.get('browser_identity_ref')
        if identity not in identities:
            continue
        try:
            same_origin = bool(target) and _canonical_web_origin(
                scope.get('browser_origin', '')
            ) == _canonical_web_origin(target)
        except (ValueError, TypeError):
            same_origin = False
        if not same_origin:
            continue
        options.append({
            'credential_ref': str(row['id']),
            'name': row['name'],
            'kind': row['kind'],
            'identity_ref': identity,
            'version': row['version'],
        })
    options.sort(key=lambda item: (
        definition['identity_refs'].index(item['identity_ref']),
        item['name'].lower(),
        item['credential_ref'],
    ))
    return {
        'contract_version': 'aegis.web-labs-credential-options.v1',
        'project_ref': project_id,
        'asset_ref': asset_id,
        'lab_ref': definition['id'],
        'identity_refs': definition['identity_refs'],
        'options': options,
    }


def prepare_web_lab(*, actor_id: str, project_id: str, asset_id: str,
                    lab_definition_id: str, credential_refs: list[str], depth: str) -> dict[str, Any]:
    """Preview existing records only. Execution must re-check all mutable state."""
    actor, project, asset = _accessible_scope(
        actor_id=actor_id, project_id=project_id, asset_id=asset_id,
    )
    definition = lab_definition(lab_definition_id)
    refs = normalize_credential_refs(credential_refs)
    requirements, blockers = [], []

    def check(ref: str, ready: bool, state: str, message: str, action: str,
              *, unverified: bool = False) -> None:
        requirements.append({'id': ref, 'state': 'ready' if ready else (
            'unverified' if unverified else 'blocked'), 'observed_state': state,
            'message_ar': message, 'suggested_action_ar': action})
        if not ready:
            blockers.append({'code': f'{ref}.{state}', 'requirement_ref': ref,
                             'observed_state': state, 'message_ar': message,
                             'suggested_action_ar': action})

    tenant = TenantProject.objects.filter(project_id=project_id, organization__is_active=True).first()
    tenant_ready = bool(tenant and OrganizationMembership.objects.filter(
        organization_id=tenant.organization_id, user_id=actor_id, is_active=True,
    ).exists())
    check('tenant', tenant_ready, 'available' if tenant_ready else 'unavailable',
          'فحص ارتباط المشروع بعضوية المؤسسة الحالية.', 'راجع ارتباط المشروع والعضوية من إعدادات المؤسسة الحالية.')
    target = _web_target(asset)
    check('target', bool(target), 'valid_web_url' if target else 'invalid_web_url',
          'يجب أن يكون الأصل موقعًا أو API بعنوان HTTP صالح وخالٍ من بيانات الدخول.',
          'صحح إعداد الأصل عبر واجهة الأصول الحالية.')
    authorization, _reason = current_asset_authorization(asset)
    auth_ready = bool(authorization and (asset.configuration or {}).get('authorized') is True)
    auth_state, auth_message = 'current', 'أحدث تفويض صالح ويطابق الأصل والهدف.'
    if not auth_ready:
        latest = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
        if not latest:
            auth_state, auth_message = 'missing', 'لا يوجد قرار تفويض مسجل لهذا الأصل.'
        elif not latest.authorized:
            auth_state, auth_message = 'revoked', 'أحدث قرار ألغى التفويض؛ القرار الأقدم لا يمنح حق التنفيذ.'
        elif latest.expires_at and latest.expires_at <= timezone.now():
            auth_state, auth_message = 'expired', 'انتهت صلاحية أحدث تفويض؛ يلزم قرار حالي قبل التنفيذ.'
        elif latest.valid_from > timezone.now():
            auth_state, auth_message = 'not_yet_valid', 'أحدث تفويض لم يبدأ سريانه بعد.'
        elif latest.asset_identity_snapshot != asset.id or latest.target_snapshot != asset_target(asset):
            auth_state, auth_message = 'binding_mismatch', 'هوية الأصل أو عنوانه تغيّر عن لقطة التفويض.'
        else:
            auth_state, auth_message = 'projection_disabled', 'حالة التفويض في إعداد الأصل غير مفعلة.'
    check('authorization', auth_ready, auth_state, auth_message,
          'راجع أو جدد التفويض عبر مسار تفويض الأصل الموجود.')
    # Avoid provider/credential metadata disclosure without an active tenant binding.
    provider, operations = _provider_metadata(project_id) if tenant_ready else (
        {'state': 'tenant_unavailable', 'decision_ref': None}, [])
    check('provider', provider['state'] == 'metadata_ready', provider['state'], {
          'missing': 'لا يوجد قرار قبول لمزود Burp في المشروع.',
          'ambiguous': 'يوجد أكثر من مزود؛ لا نختار أحدها تلقائيًا.',
          'tenant_unavailable': 'لم نقرأ بيانات المزود لعدم توفر ارتباط المؤسسة والعضوية.',
          'inadmissible': 'أحدث قرار للمزود أو لقطة قبوله غير صالح وفق سياسة القبول الحالية؛ لا نرجع إلى قبول أقدم.',
          'invalid_tool_mapping': 'بيان أدوات المزود يحتوي ربطًا لا تقبله بوابة Burp الحالية.',
          'invalid_endpoint': 'عنوان اتصال المزود لا يطابق صيغة أو سياسة بوابة Burp الحالية.',
          'metadata_ready': 'قرار المزود وبيانه مقبولان؛ الاتصال والأدوات الحية لم يُفحصا.',
          'invalid_transport': 'تعريف النقل أو بصمة مخطط الأداة غير متوافقين مع عقد Burp المعتمد.',
          }[provider['state']],
          'راجع قبول مزود Burp وإصداره وبيانه في شاشة المزودين الحالية؛ تعدد المزودين يحتاج اختيارًا صريحًا.')
    credentials, credentials_ready = _credential_metadata(
        project_id, refs, target, definition['identity_refs'],
    ) if tenant_ready else ([], False)
    check('credentials', credentials_ready, 'metadata_ready' if credentials_ready else 'incomplete_or_invalid',
          'يلزم مرجعان مختلفان لهويتي alice وbob، من المشروع نفسه وبنطاق browser_origin مطابق.',
          'اربط مرجعي TOKEN أو GENERIC في الخزنة الحالية؛ هذا الفحص لا يفك السر ولا يثبت صلاحية الجلسة.')
    required_operation = definition['required_operation']
    request_ready = (required_operation in operations
                     and provider['state'] == 'metadata_ready')
    check('request_operation', request_ready,
          'pinned_recipe_available' if request_ready else 'unsupported',
          'وصفة GET محدودة تربط هويتي Alice وBob عبر بوابة Burp الحالية؛ توفرها لا يثبت نتيجة اللاب.',
          'اختر مزود SSE المقبول ومرجعي الهوية؛ الحكم المستقل يتطلب سجل فحص موثوق للنسخة الحية.')
    capability_id = definition['required_capability_id']
    capability = CAPABILITIES.get(capability_id)
    check('canonical_capability', capability is not None,
          'registered' if capability else 'not_registered',
          'فحص تسجيل قدرة المختبر ضمن سجل القدرات الحالي؛ التسجيل وحده لا يثبت التشغيل.',
          'استخدم مسار capability execute الحالي بوضع lab_sequence مع إعادة فحص التفويض.')
    check('fixture_binding', False, 'not_verified',
          'بصمة تعريف الهدف مثبتة، لكن نسخة الهدف الحية وربطها بالأصل لم يُتحققا.',
          'اربط سجل فحص الحاوية الموقّع عند تنفيذ verified_lab_sequence؛ المعاينة لا تفك المفتاح ولا تتحقق من الهدف.', unverified=True)
    check('runtime', False, 'not_checked',
          'لم نفحص اتصال Burp أو العامل أو صلاحية الجلسات؛ لا توجد نتيجة تشغيل في هذه المعاينة.',
          'نفذ اختبارات التوافق والتحقق في المراحل اللاحقة؛ أعد فحص التفويض عند التنفيذ.', unverified=True)
    methodology = WSTGCatalog().resolve(definition['methodology_id'])
    return {
        'contract_version': CONTRACT_VERSION, 'project_ref': project_id, 'asset_ref': asset_id,
        'lab_ref': definition['id'], 'fixture_revision': definition['fixture_revision_sha256'],
        'methodology_refs': [methodology.id], 'depth': depth,
        'preview_only': True, 'execution_ready': not blockers,
        'metadata_ready': all(r['state'] == 'ready' for r in requirements
                              if r['id'] in {'tenant', 'target', 'authorization', 'provider', 'credentials'}),
        'authorization_ref': str(authorization.id) if authorization else None,
        'provider': provider, 'credential_metadata': credentials,
        'supported_operations': operations,
        'capabilities': [{'id': capability_id, 'registered': capability is not None,
                          'runtime_verified': False}],
        'requirements': requirements, 'blockers': blockers,
        'explanation_ar': 'هذه معاينة للجاهزية وليست تفويضًا أو محاولة حل. لا تنشئ مهمة ولا ترسل طلبًا إلى الهدف.',
    }
