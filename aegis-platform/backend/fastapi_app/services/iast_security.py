from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid5

from django.db import IntegrityError, transaction
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from enterprise.iast_models import IASTObservation, IASTSession
from enterprise.models import Organization, OrganizationMembership, TenantProject

from .audit_writer import add_audit_entry
from .authorization_guard import asset_target
from .evidence_identity import evidence_id
from .evidence_qualification import EvidenceQualificationPolicy, qualify_evidence
from .native_finding_projection import sync_scan_finding_counts


IAST_POLICY_VERSION = 'iast-enterprise.v1'
IAST_EVIDENCE_POLICY_VERSION = 'iast-runtime-evidence.v1'
IAST_CAPABILITY_ID = 'iast.runtime-taint-flow'
IAST_FINDING_NAMESPACE = UUID('3c9ff97a-ae3f-4b55-9cc5-8a83d1889370')

_ALLOWED_MODES = {'agent', 'sdk', 'sidecar'}
_ALLOWED_KINDS = {'taint-flow', 'runtime-sink-reachability', 'runtime-policy-violation'}
_ALLOWED_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}
_ALLOWED_CONFIDENCE = {'confirmed', 'high', 'medium', 'low'}
_LABEL_RE = re.compile(r'^[a-zA-Z0-9_.:/-]{1,80}$')


class IASTError(ValueError):
    pass


class IASTAuthorizationError(IASTError):
    pass


class IASTConflict(IASTError):
    pass


@dataclass(frozen=True)
class IASTSessionResult:
    session: IASTSession
    replayed: bool


@dataclass(frozen=True)
class IASTObservationResult:
    observation: IASTObservation
    replayed: bool

    @property
    def finding(self) -> Vulnerability:
        return self.observation.finding

    @property
    def evidence(self) -> Evidence:
        return self.observation.evidence


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, field: str, maximum: int, required: bool = True) -> str:
    normalized = ' '.join(str(value or '').split())
    if required and not normalized:
        raise IASTError(f'{field} is required.')
    if len(normalized) > maximum:
        raise IASTError(f'{field} exceeds {maximum} characters.')
    return normalized


def _idempotency(value: str) -> str:
    normalized = _text(value, field='idempotency_key', maximum=128)
    if any(ch.isspace() for ch in normalized):
        raise IASTError('idempotency_key cannot contain whitespace.')
    return normalized


def _provider_identity(value: str) -> str:
    normalized = _text(value, field='provider_identity', maximum=255)
    if any(ch in normalized for ch in '\r\n\x00'):
        raise IASTError('provider_identity contains invalid control characters.')
    return normalized


def _labels(values: list[str] | tuple[str, ...] | None) -> list[str]:
    result: list[str] = []
    for raw in list(values or [])[:32]:
        value = str(raw or '').strip()
        if not _LABEL_RE.fullmatch(value):
            raise IASTError('data_labels may contain only bounded classification labels, never raw values.')
        if value not in result:
            result.append(value)
    return sorted(result)


def _project_access(project: Project, actor_id: str) -> bool:
    if str(project.owner_id) == str(actor_id):
        return True
    return project.members.filter(pk=actor_id).exists()


def _lock_context(
    *,
    project_id: str,
    asset_id: str,
    scan_id: str,
    authorization_id: str,
    actor_id: str,
) -> tuple[Organization, Project, Asset, Scan, AssetAuthorization]:
    link_identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if link_identity is None:
        raise IASTAuthorizationError('Project is not bound to an active enterprise tenant.')

    organization = (
        Organization.objects.select_for_update()
        .filter(pk=link_identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        raise IASTAuthorizationError('Enterprise tenant is not active.')

    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=link_identity['id'], organization_id=organization.id, project_id=project_id)
        .first()
    )
    if link is None:
        raise IASTAuthorizationError('Enterprise tenant/project binding changed during IAST authorization.')

    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None or not _project_access(project, actor_id):
        raise IASTAuthorizationError('Actor is not authorized for the requested project.')
    if not OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
    ).exists():
        raise IASTAuthorizationError('Actor has no active enterprise tenant membership.')

    asset = (
        Asset.objects.select_for_update(of=('self',))
        .filter(pk=asset_id, project_id=project.id, is_active=True)
        .first()
    )
    if asset is None:
        raise IASTAuthorizationError('Active IAST asset was not found in the requested project.')

    scan = (
        Scan.objects.select_for_update(of=('self',))
        .filter(pk=scan_id, project_id=project.id, asset_id=asset.id)
        .first()
    )
    if scan is None:
        raise IASTAuthorizationError('IAST scan is not bound to the requested project and asset.')

    decision = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(pk=authorization_id, asset_id=asset.id)
        .first()
    )
    if decision is None:
        raise IASTAuthorizationError('IAST authorization decision is not bound to the requested asset.')

    latest = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(asset_id=asset.id)
        .order_by('-created_at', '-id')
        .first()
    )
    target = asset_target(asset)
    if latest is None or latest.id != decision.id:
        raise IASTAuthorizationError('IAST authorization has been superseded.')
    if decision.asset_identity_snapshot != asset.id:
        raise IASTAuthorizationError('IAST authorization asset identity no longer matches.')
    if decision.authorized is not True or not decision.is_currently_valid:
        raise IASTAuthorizationError('IAST authorization is not currently valid.')
    if not target or decision.target_snapshot != target:
        raise IASTAuthorizationError('IAST target no longer matches the authorization snapshot.')
    if scan.authorization_decision_id != decision.id:
        raise IASTAuthorizationError('IAST scan is not bound to the current authorization decision.')
    if dict(asset.configuration or {}).get('authorized') is not True:
        raise IASTAuthorizationError('IAST asset authorization projection is not enabled.')

    return organization, project, asset, scan, decision


def _session_contract(*, provider_identity: str, instrumentation_mode: str, target: str) -> dict[str, Any]:
    return {
        'schema': 'aegis.iast-session.v1',
        'policy_version': IAST_POLICY_VERSION,
        'capability_id': IAST_CAPABILITY_ID,
        'provider_identity_sha256': hashlib.sha256(provider_identity.encode('utf-8')).hexdigest(),
        'instrumentation_mode': instrumentation_mode,
        'target': target,
        'accepted_observation_kinds': sorted(_ALLOWED_KINDS),
        'redaction': {
            'raw_request_bodies': False,
            'raw_response_bodies': False,
            'secret_values': False,
            'credential_values': False,
            'data_labels_only': True,
        },
    }


def start_iast_session(
    *,
    project_id: str,
    asset_id: str,
    scan_id: str,
    authorization_id: str,
    actor_id: str,
    provider_identity: str,
    instrumentation_mode: str,
    idempotency_key: str,
) -> IASTSessionResult:
    provider = _provider_identity(provider_identity)
    mode = _text(instrumentation_mode, field='instrumentation_mode', maximum=32).lower()
    if mode not in _ALLOWED_MODES:
        raise IASTError(f'instrumentation_mode must be one of {sorted(_ALLOWED_MODES)}.')
    idem = _idempotency(idempotency_key)

    with transaction.atomic():
        organization, project, asset, scan, decision = _lock_context(
            project_id=str(project_id),
            asset_id=str(asset_id),
            scan_id=str(scan_id),
            authorization_id=str(authorization_id),
            actor_id=str(actor_id),
        )
        contract = _session_contract(
            provider_identity=provider,
            instrumentation_mode=mode,
            target=decision.target_snapshot,
        )
        contract_fingerprint = _sha(contract)
        request = {
            'organization_id': str(organization.id),
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id),
            'authorization_id': str(decision.id),
            'actor_id': str(actor_id),
            'provider_identity': provider,
            'instrumentation_mode': mode,
            'idempotency_key': idem,
            'contract_fingerprint': contract_fingerprint,
        }
        request_fingerprint = _sha(request)

        existing = IASTSession.objects.filter(
            organization=organization,
            idempotency_key=idem,
        ).select_related(
            'organization', 'project', 'asset', 'scan', 'authorization_decision', 'created_by'
        ).first()
        if existing is not None:
            if existing.request_fingerprint != request_fingerprint:
                raise IASTConflict('IAST session idempotency key is already bound to a different request.')
            return IASTSessionResult(session=existing, replayed=True)

        try:
            session = IASTSession.objects.create(
                organization=organization,
                project=project,
                asset=asset,
                scan=scan,
                authorization_decision=decision,
                created_by_id=actor_id,
                provider_identity=provider,
                provider_identity_sha256=hashlib.sha256(provider.encode('utf-8')).hexdigest(),
                instrumentation_mode=mode,
                target_snapshot=decision.target_snapshot,
                idempotency_key=idem,
                request_fingerprint=request_fingerprint,
                policy_version=IAST_POLICY_VERSION,
                contract_snapshot=contract,
                contract_fingerprint=contract_fingerprint,
            )
        except IntegrityError as exc:
            raise IASTConflict('IAST session could not be committed idempotently.') from exc

        add_audit_entry(
            user=actor_id,
            action='iast.session.create',
            target=str(session.id),
            project=str(project.id),
            resource_type='iast_session',
            resource_repr=provider,
            metadata={
                'organization_id': str(organization.id),
                'asset_id': str(asset.id),
                'scan_id': str(scan.id),
                'authorization_decision_id': str(decision.id),
                'request_fingerprint': request_fingerprint,
                'contract_fingerprint': contract_fingerprint,
                'policy_version': IAST_POLICY_VERSION,
            },
        )
        return IASTSessionResult(session=session, replayed=False)


def _observation_snapshot(
    *,
    observation_kind: str,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    confidence: str,
    source_kind: str,
    sink_kind: str,
    location: str,
    trace_id: str,
    data_labels: list[str],
    cwe_id: str,
    owasp_category: str,
    remediation: str,
    method: str,
    parameter: str,
    file_path: str,
    line: int | None,
    function_name: str,
) -> dict[str, Any]:
    return {
        'schema': 'aegis.iast-runtime-observation.v1',
        'kind': observation_kind,
        'rule_id': rule_id,
        'title': title,
        'description': description,
        'severity': severity,
        'confidence': confidence,
        'source_kind': source_kind,
        'sink_kind': sink_kind,
        'location': location,
        'trace_id': trace_id,
        'data_labels': data_labels,
        'cwe_id': cwe_id,
        'owasp_category': owasp_category,
        'remediation': remediation,
        'method': method,
        'parameter': parameter,
        'file_path': file_path,
        'line': line,
        'function_name': function_name,
        'raw_values_captured': False,
    }


def _finding_id(scan_id: str, snapshot: dict[str, Any]) -> UUID:
    identity = '|'.join(
        str(snapshot.get(key) or '').strip().lower()
        for key in ('rule_id', 'location', 'source_kind', 'sink_kind', 'file_path', 'line', 'function_name')
    )
    return uuid5(IAST_FINDING_NAMESPACE, f'{str(scan_id).lower()}:{identity}')


def _existing_observation_result(
    *,
    session: IASTSession,
    idempotency_key: str,
    request_fingerprint: str,
    observation_sha256: str,
) -> IASTObservationResult | None:
    existing_by_idem = (
        IASTObservation.objects.select_related('finding', 'evidence', 'qualification')
        .filter(session=session, idempotency_key=idempotency_key)
        .first()
    )
    if existing_by_idem is not None:
        if existing_by_idem.request_fingerprint != request_fingerprint:
            raise IASTConflict('IAST observation idempotency key is already bound to a different request.')
        return IASTObservationResult(observation=existing_by_idem, replayed=True)

    existing_by_hash = (
        IASTObservation.objects.select_related('finding', 'evidence', 'qualification')
        .filter(session=session, observation_sha256=observation_sha256)
        .first()
    )
    if existing_by_hash is not None:
        return IASTObservationResult(observation=existing_by_hash, replayed=True)
    return None


def ingest_iast_observation(
    *,
    session_id: str,
    actor_id: str,
    idempotency_key: str,
    observation_kind: str,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    confidence: str,
    source_kind: str,
    sink_kind: str,
    trace_id: str,
    data_labels: list[str] | tuple[str, ...] | None = None,
    location: str = '',
    cwe_id: str = '',
    owasp_category: str = '',
    remediation: str = '',
    method: str = '',
    parameter: str = '',
    file_path: str = '',
    line: int | None = None,
    function_name: str = '',
) -> IASTObservationResult:
    idem = _idempotency(idempotency_key)
    kind = _text(observation_kind, field='observation_kind', maximum=64).lower()
    if kind not in _ALLOWED_KINDS:
        raise IASTError(f'observation_kind must be one of {sorted(_ALLOWED_KINDS)}.')
    normalized_severity = _text(severity, field='severity', maximum=16).lower()
    if normalized_severity not in _ALLOWED_SEVERITIES:
        raise IASTError('Unsupported IAST severity.')
    normalized_confidence = _text(confidence, field='confidence', maximum=16).lower()
    if normalized_confidence not in _ALLOWED_CONFIDENCE:
        raise IASTError('Unsupported IAST confidence.')

    source = _text(source_kind, field='source_kind', maximum=100)
    sink = _text(sink_kind, field='sink_kind', maximum=100)
    if kind == 'taint-flow' and (not source or not sink):
        raise IASTError('taint-flow observations require both source_kind and sink_kind.')

    if line is not None:
        try:
            line = int(line)
        except (TypeError, ValueError) as exc:
            raise IASTError('line must be an integer.') from exc
        if line < 1 or line > 10_000_000:
            raise IASTError('line is outside the accepted range.')

    snapshot = _observation_snapshot(
        observation_kind=kind,
        rule_id=_text(rule_id, field='rule_id', maximum=200),
        title=_text(title, field='title', maximum=300),
        description=_text(description, field='description', maximum=5000),
        severity=normalized_severity,
        confidence=normalized_confidence,
        source_kind=source,
        sink_kind=sink,
        location=_text(location, field='location', maximum=500, required=False),
        trace_id=_text(trace_id, field='trace_id', maximum=128),
        data_labels=_labels(data_labels),
        cwe_id=_text(cwe_id, field='cwe_id', maximum=20, required=False),
        owasp_category=_text(owasp_category, field='owasp_category', maximum=50, required=False),
        remediation=_text(remediation, field='remediation', maximum=5000, required=False),
        method=_text(method, field='method', maximum=10, required=False).upper(),
        parameter=_text(parameter, field='parameter', maximum=200, required=False),
        file_path=_text(file_path, field='file_path', maximum=500, required=False),
        line=line,
        function_name=_text(function_name, field='function_name', maximum=200, required=False),
    )
    observation_sha256 = _sha(snapshot)
    request_fingerprint = _sha({
        'session_id': str(session_id),
        'actor_id': str(actor_id),
        'idempotency_key': idem,
        'observation_sha256': observation_sha256,
    })

    with transaction.atomic():
        session = (
            IASTSession.objects.select_for_update(of=('self',))
            .select_related('organization', 'project', 'asset', 'scan', 'authorization_decision')
            .filter(pk=session_id)
            .first()
        )
        if session is None:
            raise IASTAuthorizationError('IAST session was not found.')

        organization, project, asset, scan, decision = _lock_context(
            project_id=str(session.project_id),
            asset_id=str(session.asset_id),
            scan_id=str(session.scan_id),
            authorization_id=str(session.authorization_decision_id),
            actor_id=str(actor_id),
        )
        if organization.id != session.organization_id:
            raise IASTAuthorizationError('IAST tenant lineage changed before observation commit.')
        if session.target_snapshot != decision.target_snapshot:
            raise IASTAuthorizationError('IAST target snapshot changed before observation commit.')
        if session.policy_version != IAST_POLICY_VERSION:
            raise IASTAuthorizationError('IAST session policy version is no longer accepted.')

        replay = _existing_observation_result(
            session=session,
            idempotency_key=idem,
            request_fingerprint=request_fingerprint,
            observation_sha256=observation_sha256,
        )
        if replay is not None:
            return replay

        finding_pk = _finding_id(str(scan.id), snapshot)
        location_value = snapshot['location']
        finding_defaults = {
            'scan': scan,
            'project': project,
            'asset': asset,
            'title': snapshot['title'],
            'description': snapshot['description'],
            'severity': snapshot['severity'],
            'status': Vulnerability.Status.OPEN,
            'confidence': snapshot['confidence'],
            'category': 'iast-runtime-security',
            'cwe_id': snapshot['cwe_id'],
            'owasp_category': snapshot['owasp_category'],
            'tags': ['aegisscan-iast', IAST_CAPABILITY_ID, snapshot['rule_id']],
            'file_path': snapshot['file_path'],
            'line_start': snapshot['line'],
            'function_name': snapshot['function_name'],
            'url': location_value if location_value.startswith(('http://', 'https://')) else '',
            'parameter': snapshot['parameter'],
            'method': snapshot['method'],
            'risk_score': {
                'critical': 9.5,
                'high': 8.0,
                'medium': 5.0,
                'low': 2.0,
                'info': 0.5,
            }[snapshot['severity']],
            'evidence_count': 1,
            'remediation': snapshot['remediation'],
            'fix_available': bool(snapshot['remediation']),
            'source_engine': 'iast',
            'raw_data': {
                'schema': 'aegis.iast-finding.v1',
                'capability_id': IAST_CAPABILITY_ID,
                'rule_id': snapshot['rule_id'],
                'source_kind': snapshot['source_kind'],
                'sink_kind': snapshot['sink_kind'],
                'trace_id': snapshot['trace_id'],
                'data_labels': snapshot['data_labels'],
                'session_id': str(session.id),
                'authorization_decision_id': str(decision.id),
                'observation_sha256': observation_sha256,
                'raw_values_captured': False,
            },
        }
        finding, created = Vulnerability.objects.get_or_create(id=finding_pk, defaults=finding_defaults)
        if not created:
            if finding.project_id != project.id or finding.asset_id != asset.id or finding.scan_id != scan.id:
                raise IASTConflict('Deterministic IAST finding identity collided across security boundaries.')
            finding.last_seen = timezone.now()
            finding.evidence_count = max(1, int(finding.evidence_count or 0) + 1)
            finding.save(update_fields=['last_seen', 'evidence_count', 'updated_at'])

        evidence_payload = {
            **snapshot,
            'session_id': str(session.id),
            'organization_id': str(organization.id),
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id),
            'finding_id': str(finding.id),
            'authorization_decision_id': str(decision.id),
            'provider_identity_sha256': session.provider_identity_sha256,
            'observation_sha256': observation_sha256,
        }
        evidence_pk = evidence_id(
            'iast',
            f'{session.id}:{observation_sha256}',
            'iast',
            'runtime_observation',
            str(finding.id),
        )
        evidence = Evidence.objects.create(
            id=evidence_pk,
            scan=scan,
            asset=asset,
            finding=finding,
            source='iast',
            evidence_type='runtime_observation',
            raw_output=_canonical(evidence_payload).decode('utf-8'),
            metadata={
                'schema': 'aegis.iast-evidence.v1',
                'source_capability': IAST_CAPABILITY_ID,
                'capability_id': IAST_CAPABILITY_ID,
                'organization_id': str(organization.id),
                'project_id': str(project.id),
                'subject_type': 'finding',
                'subject_id': str(finding.id),
                'target': session.target_snapshot,
                'authorization_decision_id': str(decision.id),
                'execution_ref': str(session.id),
                'provider_identity_sha256': session.provider_identity_sha256,
                'observation_sha256': observation_sha256,
                'request_fingerprint': request_fingerprint,
                'raw_values_captured': False,
            },
            collected_by_id=actor_id,
        )

        qualification_result = qualify_evidence(
            project_id=str(project.id),
            organization_id=str(organization.id),
            evidence_ids=[str(evidence.id)],
            subject_type='finding',
            subject_id=str(finding.id),
            target=session.target_snapshot,
            authorization_ref=str(decision.id),
            execution_ref=str(session.id),
            requested_by_id=str(actor_id),
            policy=EvidenceQualificationPolicy(
                policy_version=IAST_EVIDENCE_POLICY_VERSION,
                min_count=1,
                evidence_types=('runtime_observation',),
                source_capabilities=(IAST_CAPABILITY_ID,),
                require_subject=True,
                require_target=True,
                require_authorization=True,
                require_execution=True,
                require_producer=True,
            ),
        )
        if not qualification_result.qualified:
            raise IASTAuthorizationError(
                f'IAST evidence failed qualification: {qualification_result.evaluation.decision}.'
            )

        try:
            observation = IASTObservation.objects.create(
                session=session,
                finding=finding,
                evidence=evidence,
                qualification=qualification_result.evaluation,
                observed_by_id=actor_id,
                observation_kind=snapshot['kind'],
                rule_id=snapshot['rule_id'],
                severity=snapshot['severity'],
                confidence=snapshot['confidence'],
                source_kind=snapshot['source_kind'],
                sink_kind=snapshot['sink_kind'],
                location=snapshot['location'],
                trace_id=snapshot['trace_id'],
                data_labels=snapshot['data_labels'],
                metadata_snapshot=snapshot,
                idempotency_key=idem,
                request_fingerprint=request_fingerprint,
                observation_sha256=observation_sha256,
            )
        except IntegrityError as exc:
            raise IASTConflict('IAST observation could not be committed idempotently.') from exc

        sync_scan_finding_counts(scan)
        add_audit_entry(
            user=actor_id,
            action='iast.observation.commit',
            target=str(observation.id),
            project=str(project.id),
            resource_type='iast_observation',
            resource_repr=snapshot['rule_id'],
            metadata={
                'organization_id': str(organization.id),
                'session_id': str(session.id),
                'asset_id': str(asset.id),
                'scan_id': str(scan.id),
                'finding_id': str(finding.id),
                'evidence_id': str(evidence.id),
                'qualification_id': str(qualification_result.evaluation.id),
                'authorization_decision_id': str(decision.id),
                'observation_sha256': observation_sha256,
                'request_fingerprint': request_fingerprint,
                'policy_version': IAST_POLICY_VERSION,
            },
        )
        return IASTObservationResult(observation=observation, replayed=False)
