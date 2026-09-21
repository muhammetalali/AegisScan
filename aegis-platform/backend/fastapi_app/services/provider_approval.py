from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.projects.models import Project, ProjectMembership
from enterprise.models import Organization, OrganizationMembership, TenantProject
from enterprise.provider_approval_models import ProviderApprovalDecision
from enterprise.web_security_models import ProviderApprovalRecord

from .audit_writer import add_audit_entry


PROVIDER_APPROVAL_POLICY_VERSION = 'provider-approval-enterprise.v1'
_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,179}$')
_VERSION_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,119}$')
_CAPABILITY_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,179}$')


class ProviderApprovalError(ValueError):
    pass


class ProviderApprovalAuthorizationError(ProviderApprovalError):
    pass


class ProviderApprovalConflict(ProviderApprovalError):
    pass


@dataclass(frozen=True)
class ProviderDecisionResult:
    decision: ProviderApprovalDecision
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    ).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, field: str, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    normalized = ' '.join(str(value or '').split())
    if not normalized:
        raise ProviderApprovalError(f'{field} is required.')
    if len(normalized) > maximum or any(ch in normalized for ch in '\r\n\x00'):
        raise ProviderApprovalError(f'{field} is invalid.')
    if pattern is not None and not pattern.fullmatch(normalized):
        raise ProviderApprovalError(f'{field} contains unsupported characters.')
    return normalized


def _hex_digest(value: Any, *, field: str) -> str:
    normalized = str(value or '').strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ProviderApprovalError(f'{field} must be a lowercase SHA-256 digest.')
    return normalized


def _active_tenant(project_id: str) -> tuple[Organization, TenantProject] | None:
    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if identity is None:
        return None
    organization = (
        Organization.objects.select_for_update()
        .filter(pk=identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        return None
    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=identity['id'], organization_id=organization.id, project_id=project_id)
        .first()
    )
    if link is None:
        return None
    return organization, link


def _assert_reviewer(project: Project, organization: Organization, actor_id: str) -> None:
    project_allowed = str(project.owner_id) == str(actor_id) or ProjectMembership.objects.filter(
        project=project,
        user_id=actor_id,
        role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN],
    ).exists()
    if not project_allowed:
        raise ProviderApprovalAuthorizationError('Provider approval requires project owner/admin authority.')

    org_allowed = OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
        role__in=[
            OrganizationMembership.Role.OWNER,
            OrganizationMembership.Role.ADMIN,
            OrganizationMembership.Role.MANAGER,
        ],
    ).exists()
    if not org_allowed:
        raise ProviderApprovalAuthorizationError('Provider approval requires active enterprise governance authority.')


def _capability_manifest(capability: str, manifest: dict[str, Any]) -> dict[str, Any]:
    operations = manifest.get('mcp_tools')
    if isinstance(operations, dict):
        operation_names = sorted(str(key) for key in operations if str(key).strip())
    else:
        operation_names = []
    execution_classes = manifest.get('execution_classes')
    if not isinstance(execution_classes, list):
        execution_classes = ['governed-provider']
    return {
        'schema': 'aegis.provider-capability-manifest.v1',
        'capabilities': [capability],
        'operations': operation_names,
        'execution_classes': sorted({str(item)[:100] for item in execution_classes if str(item).strip()}),
        'network_permissions': sorted({
            str(item)[:200]
            for item in (manifest.get('network_permissions') or [])
            if str(item).strip()
        }),
    }


def _supply_chain_snapshot(manifest: dict[str, Any]) -> dict[str, Any]:
    critical = manifest.get('unmitigated_critical_cves')
    if not isinstance(critical, list):
        critical = []
    return {
        'schema': 'aegis.provider-supply-chain.v1',
        'sbom_present': manifest.get('sbom') is True,
        'supply_chain_integrity': manifest.get('supply_chain_integrity') is True,
        'sbom_sha256': str(manifest.get('sbom_sha256') or '').strip().lower(),
        'provenance_sha256': str(manifest.get('provenance_sha256') or '').strip().lower(),
        'artifact_sha256': str(manifest.get('artifact_sha256') or '').strip().lower(),
        'signature_identity': str(manifest.get('signature_identity') or '').strip()[:500],
        'signature_verified': manifest.get('signature_verified') is True,
        'reproducible_build': manifest.get('ci_reproducibility') is True,
        'critical_cves': sorted(str(item)[:100] for item in critical),
    }


def _supply_chain_failures(snapshot: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if snapshot.get('sbom_present') is not True:
        failures.append('SBOM is not proven')
    if snapshot.get('supply_chain_integrity') is not True:
        failures.append('supply-chain integrity is not proven')
    for field in ('sbom_sha256', 'provenance_sha256', 'artifact_sha256'):
        if not _SHA256_RE.fullmatch(str(snapshot.get(field) or '')):
            failures.append(f'{field} is missing or invalid')
    if not str(snapshot.get('signature_identity') or '').strip():
        failures.append('signature identity is missing')
    if snapshot.get('signature_verified') is not True:
        failures.append('artifact signature is not verified')
    if snapshot.get('reproducible_build') is not True:
        failures.append('build reproducibility is not proven')
    if snapshot.get('critical_cves'):
        failures.append('provider has unmitigated critical CVEs')
    return failures


def _manifest_failures(manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for field in ('determinism', 'evidence_quality', 'ci_reproducibility'):
        if manifest.get(field) is not True:
            failures.append(f'{field} is not proven')
    maintenance = manifest.get('maintenance')
    if not isinstance(maintenance, dict) or maintenance.get('status') not in {'active', 'maintained'}:
        failures.append('provider is not actively maintained')
    privileges = {str(item).lower() for item in (manifest.get('container_privileges') or [])}
    forbidden = privileges.intersection({'privileged', 'hostnetwork', 'hostpid', 'hostipc', 'docker-socket'})
    if forbidden:
        failures.append('forbidden provider privileges: ' + ', '.join(sorted(forbidden)))
    return failures


def _trust_state(status: str, manifest: dict[str, Any], supply_chain: dict[str, Any]) -> str:
    if status in {
        ProviderApprovalDecision.Status.REVOKED,
        ProviderApprovalDecision.Status.REJECTED,
    }:
        return ProviderApprovalDecision.TrustState.UNTRUSTED
    failures = _manifest_failures(manifest) + _supply_chain_failures(supply_chain)
    if status == ProviderApprovalDecision.Status.APPROVED and not failures:
        return ProviderApprovalDecision.TrustState.TRUSTED
    return ProviderApprovalDecision.TrustState.CONDITIONAL


def _legacy_status(status: str) -> str:
    if status == ProviderApprovalDecision.Status.REVOKED:
        return ProviderApprovalRecord.Status.REJECTED
    valid = {
        ProviderApprovalRecord.Status.APPROVED,
        ProviderApprovalRecord.Status.EXPERIMENTAL,
        ProviderApprovalRecord.Status.RESTRICTED,
        ProviderApprovalRecord.Status.REJECTED,
    }
    if status not in valid:
        raise ProviderApprovalError('Unsupported provider decision status.')
    return status


def _identity_digest(
    *,
    provider_name: str,
    provider_version: str,
    capability: str,
    manifest_sha256: str,
    supply_chain: dict[str, Any],
) -> str:
    return _sha({
        'provider_name': provider_name,
        'provider_version': provider_version,
        'capability': capability,
        'manifest_sha256': manifest_sha256,
        'artifact_sha256': supply_chain.get('artifact_sha256'),
        'signature_identity': supply_chain.get('signature_identity'),
    })


@transaction.atomic
def record_provider_decision(
    *,
    project_id: str,
    actor_id: str,
    provider_name: str,
    provider_version: str,
    capability: str,
    status: str,
    manifest: dict[str, Any],
    rationale: str = '',
    expires_at: datetime | None = None,
    legacy_approval: ProviderApprovalRecord | None = None,
) -> ProviderDecisionResult:
    name = _text(provider_name, field='provider_name', maximum=180, pattern=_NAME_RE)
    version = _text(provider_version, field='provider_version', maximum=120, pattern=_VERSION_RE)
    capability_id = _text(capability, field='capability', maximum=180, pattern=_CAPABILITY_RE)
    normalized_status = str(status or '').strip().lower()
    valid_statuses = {choice for choice, _label in ProviderApprovalDecision.Status.choices}
    if normalized_status not in valid_statuses:
        raise ProviderApprovalError('Unsupported provider decision status.')
    if not isinstance(manifest, dict) or not manifest:
        raise ProviderApprovalError('Provider manifest must be a non-empty object.')
    if expires_at is not None and timezone.is_naive(expires_at):
        raise ProviderApprovalError('expires_at must be timezone-aware.')

    # Preserve the enterprise serialization order used by AGOM:
    # Organization -> TenantProject -> Project.
    tenant = _active_tenant(str(project_id))
    if tenant is None:
        raise ProviderApprovalAuthorizationError('Provider project is not bound to an active enterprise tenant.')
    organization, _link = tenant
    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None:
        raise ProviderApprovalAuthorizationError('Provider project was not found.')
    _assert_reviewer(project, organization, str(actor_id))

    manifest_snapshot = json.loads(_canonical(manifest).decode('utf-8'))
    manifest_sha256 = _sha(manifest_snapshot)
    capability_snapshot = _capability_manifest(capability_id, manifest_snapshot)
    capability_sha256 = _sha(capability_snapshot)
    supply_chain = _supply_chain_snapshot(manifest_snapshot)
    supply_chain_sha256 = _sha(supply_chain)
    trust_state = _trust_state(normalized_status, manifest_snapshot, supply_chain)
    provider_identity_sha256 = _identity_digest(
        provider_name=name,
        provider_version=version,
        capability=capability_id,
        manifest_sha256=manifest_sha256,
        supply_chain=supply_chain,
    )

    if legacy_approval is None:
        legacy_status = _legacy_status(normalized_status)
        legacy_approval, _created = ProviderApprovalRecord.objects.get_or_create(
            project=project,
            provider_name=name,
            provider_version=version,
            capability=capability_id,
            status=legacy_status,
            manifest_sha256=manifest_sha256,
            defaults={
                'manifest': manifest_snapshot,
                'rationale': rationale,
                'reviewed_by_id': actor_id,
            },
        )
    elif legacy_approval.project_id != project.id:
        raise ProviderApprovalConflict('Legacy provider approval belongs to another project.')

    previous = (
        ProviderApprovalDecision.objects.select_for_update()
        .filter(project=project, provider_name=name, capability=capability_id)
        .order_by('-decision_version', '-created_at', '-id')
        .first()
    )
    if (
        previous is not None
        and str(previous.legacy_approval_id or '') == str(legacy_approval.id)
        and previous.provider_version == version
        and previous.status == normalized_status
        and previous.manifest_sha256 == manifest_sha256
        and previous.capability_manifest_sha256 == capability_sha256
        and previous.supply_chain_sha256 == supply_chain_sha256
        and previous.expires_at == expires_at
    ):
        return ProviderDecisionResult(decision=previous, replayed=True)

    next_version = int(previous.decision_version) + 1 if previous else 1

    request_fingerprint = _sha({
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'actor_id': str(actor_id),
        'provider_name': name,
        'provider_version': version,
        'capability': capability_id,
        'status': normalized_status,
        'manifest_sha256': manifest_sha256,
        'capability_manifest_sha256': capability_sha256,
        'supply_chain_sha256': supply_chain_sha256,
        'legacy_approval_id': str(legacy_approval.id),
        'predecessor_id': str(previous.id) if previous else '',
        'decision_version': next_version,
        'expires_at': expires_at.isoformat() if expires_at else '',
    })
    replay = ProviderApprovalDecision.objects.filter(request_fingerprint=request_fingerprint).first()
    if replay is not None:
        return ProviderDecisionResult(decision=replay, replayed=True)

    decision = ProviderApprovalDecision.objects.create(
        organization=organization,
        project=project,
        legacy_approval=legacy_approval,
        predecessor=previous,
        reviewed_by_id=actor_id,
        provider_name=name,
        provider_version=version,
        capability=capability_id,
        provider_identity_sha256=provider_identity_sha256,
        status=normalized_status,
        trust_state=trust_state,
        decision_version=next_version,
        manifest=manifest_snapshot,
        manifest_sha256=manifest_sha256,
        capability_manifest=capability_snapshot,
        capability_manifest_sha256=capability_sha256,
        supply_chain_evidence=supply_chain,
        supply_chain_sha256=supply_chain_sha256,
        request_fingerprint=request_fingerprint,
        policy_version=PROVIDER_APPROVAL_POLICY_VERSION,
        rationale=str(rationale or '')[:5000],
        expires_at=expires_at,
    )
    add_audit_entry(
        user=str(actor_id),
        action='provider_approval.decision.commit',
        target=str(decision.id),
        project=str(project.id),
        resource_type='provider_approval_decision',
        resource_repr=f'{name}@{version}:{capability_id}',
        metadata={
            'organization_id': str(organization.id),
            'decision_version': next_version,
            'status': normalized_status,
            'trust_state': trust_state,
            'provider_identity_sha256': provider_identity_sha256,
            'manifest_sha256': manifest_sha256,
            'capability_manifest_sha256': capability_sha256,
            'supply_chain_sha256': supply_chain_sha256,
            'legacy_approval_id': str(legacy_approval.id),
            'predecessor_id': str(previous.id) if previous else '',
            'policy_version': PROVIDER_APPROVAL_POLICY_VERSION,
        },
    )
    return ProviderDecisionResult(decision=decision, replayed=False)


def mirror_legacy_provider_approval(
    record: ProviderApprovalRecord,
    actor_id: str,
) -> ProviderDecisionResult | None:
    """Promote a legacy immutable approval when enterprise tenant governance exists.

    Legacy-only projects keep their historical behavior. Enterprise-bound projects
    get an authoritative append-only decision automatically, and governed execution
    may require that decision.
    """
    if not TenantProject.objects.filter(project_id=record.project_id, organization__is_active=True).exists():
        return None
    status = str(record.status)
    return record_provider_decision(
        project_id=str(record.project_id),
        actor_id=str(actor_id),
        provider_name=record.provider_name,
        provider_version=record.provider_version,
        capability=record.capability,
        status=status,
        manifest=dict(record.manifest or {}),
        rationale=record.rationale,
        legacy_approval=record,
    )


def current_provider_decision(
    *,
    project_id: str,
    provider_name: str,
    capability: str,
) -> ProviderApprovalDecision | None:
    return (
        ProviderApprovalDecision.objects.filter(
            project_id=project_id,
            provider_name=provider_name,
            capability=capability,
        )
        .order_by('-decision_version', '-created_at', '-id')
        .first()
    )


def evaluate_provider_admissibility(
    *,
    project_id: str,
    provider_name: str,
    provider_version: str,
    capability: str,
    expected_legacy_approval_id: str | None = None,
    expected_decision_id: str | None = None,
) -> dict[str, Any]:
    decision = current_provider_decision(
        project_id=str(project_id),
        provider_name=str(provider_name),
        capability=str(capability),
    )
    failures: list[str] = []
    if decision is None:
        return {
            'allowed': False,
            'failures': ['no enterprise provider approval decision exists'],
            'decision_id': None,
            'decision_version': None,
            'policy_version': PROVIDER_APPROVAL_POLICY_VERSION,
        }

    if decision.provider_version != str(provider_version):
        failures.append('provider version is no longer the current approved version')
    if expected_legacy_approval_id and str(decision.legacy_approval_id or '') != str(expected_legacy_approval_id):
        failures.append('legacy approval pin is no longer current')
    if expected_decision_id and str(decision.id) != str(expected_decision_id):
        failures.append('enterprise decision pin is no longer current')
    if decision.status != ProviderApprovalDecision.Status.APPROVED:
        failures.append(f'provider status is {decision.status}, not approved')
    if decision.trust_state != ProviderApprovalDecision.TrustState.TRUSTED:
        failures.append(f'provider trust state is {decision.trust_state}, not trusted')
    if decision.expires_at and decision.expires_at <= timezone.now():
        failures.append('provider approval decision has expired')
    if _sha(decision.manifest or {}) != decision.manifest_sha256:
        failures.append('provider manifest integrity mismatch')
    if _sha(decision.capability_manifest or {}) != decision.capability_manifest_sha256:
        failures.append('provider capability manifest integrity mismatch')
    if _sha(decision.supply_chain_evidence or {}) != decision.supply_chain_sha256:
        failures.append('provider supply-chain evidence integrity mismatch')

    capabilities = decision.capability_manifest.get('capabilities') if isinstance(decision.capability_manifest, dict) else []
    if capability not in (capabilities or []):
        failures.append('requested capability is not admitted by the provider capability manifest')
    failures.extend(_manifest_failures(decision.manifest if isinstance(decision.manifest, dict) else {}))
    failures.extend(_supply_chain_failures(
        decision.supply_chain_evidence if isinstance(decision.supply_chain_evidence, dict) else {}
    ))

    if decision.legacy_approval_id:
        legacy = ProviderApprovalRecord.objects.filter(pk=decision.legacy_approval_id).first()
        if legacy is None:
            failures.append('legacy compatibility approval is missing')
        elif legacy.manifest_sha256 != decision.manifest_sha256:
            failures.append('legacy compatibility approval manifest drifted from enterprise decision')

    return {
        'allowed': not failures,
        'failures': sorted(set(failures)),
        'decision_id': str(decision.id),
        'decision_version': int(decision.decision_version),
        'legacy_approval_id': str(decision.legacy_approval_id or ''),
        'provider_identity_sha256': decision.provider_identity_sha256,
        'manifest_sha256': decision.manifest_sha256,
        'capability_manifest_sha256': decision.capability_manifest_sha256,
        'supply_chain_sha256': decision.supply_chain_sha256,
        'status': decision.status,
        'trust_state': decision.trust_state,
        'policy_version': decision.policy_version,
    }
