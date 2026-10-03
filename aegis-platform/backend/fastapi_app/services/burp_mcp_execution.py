from __future__ import annotations

from django.db import transaction
from enterprise.provider_approval_models import ProviderApprovalDecision

from .burp_http_probe import health_request_arguments
from .burp_lab_requests import lab_bindings
from .credential_execution import authorize_credential_refs_for_execution, credential_execution_context
from django_project.system.credential_models import CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied
from .burp_mcp_gateway import (
    BURP_MCP_CAPABILITY_ID, BurpMCPProviderError, _current_provider_approval,
)


def resolve_probe_provider(*, project_id: str, decision_ref: str, target: str):
    """Use a project-scoped current decision, never a client-supplied endpoint."""
    health_request_arguments(target)
    with transaction.atomic():
        selected = ProviderApprovalDecision.objects.filter(
            pk=decision_ref, project_id=project_id, capability=BURP_MCP_CAPABILITY_ID,
        ).first()
        if selected is None:
            raise BurpMCPProviderError('قرار مزود Burp غير متاح في المشروع الحالي.')
        _record, current, mapping, _endpoint = _current_provider_approval(
            project_id=project_id, provider_name=selected.provider_name,
            provider_version=selected.provider_version,
        )
        if current.id != selected.id:
            raise BurpMCPProviderError('قرار المزود المختار استبدل بقرار أحدث؛ حدّث المرجع.')
        if (current.manifest.get('mcp_transport') != 'sse'
                or mapping.get('burp.http_request') != 'send_http1_request'):
            raise BurpMCPProviderError('المزود لا يعلن نقل SSE وأداة HTTP المتوافقة مع فحص المختبر.')
        return current


def authorize_burp_execution(*, project_id, actor_id, target, refs, options, asset_id=None):
    if options.get('mode') not in {'lab_sequence', 'verified_lab_sequence'}:
        if len(refs) > 1:
            raise CredentialVaultDenied('The transport probe accepts at most one provider credential.')
        return authorize_credential_refs_for_execution(
            project_id=project_id, actor_id=actor_id, target=target, refs=refs,
            capability_id=BURP_MCP_CAPABILITY_ID,
            allowed_kinds=(CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.TOKEN),
            purpose='burp-mcp:probe-schedule')
    provider = options.get('provider_credential_ref')
    if provider and provider not in refs:
        raise CredentialVaultDenied('The provider credential must be bound to this execution.')
    target_refs = [ref for ref in refs if ref != provider]
    bindings = lab_bindings(project_id=project_id, actor_id=actor_id, target=target, refs=target_refs)
    if options.get('mode') == 'verified_lab_sequence':
        from .lab_verification import validate_runtime_evidence
        if not asset_id:
            raise CredentialVaultDenied('Verified BAC scheduling requires the selected asset binding.')
        validate_runtime_evidence(evidence_ref=options['runtime_evidence_ref'],
            project_id=project_id, asset_id=asset_id, target=target)
    metadata = [{'credential_ref': b['credential_ref'], 'version': b['version'], 'identity_ref': identity,
                 'role': 'target-identity'} for identity, b in sorted(bindings.items())]
    if provider:
        ctx = authorize_credential_refs_for_execution(
            project_id=project_id, actor_id=actor_id, target=target, refs=[provider],
            capability_id=BURP_MCP_CAPABILITY_ID,
            allowed_kinds=(CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.TOKEN),
            purpose='burp-mcp:provider-schedule')
        metadata += [{**row, 'role': 'provider-authentication'} for row in ctx['credential_refs']]
    return credential_execution_context(metadata, resolved=False)
