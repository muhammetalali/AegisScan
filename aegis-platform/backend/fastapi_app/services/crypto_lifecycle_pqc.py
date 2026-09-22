from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project, ProjectMembership
from enterprise.crypto_asset_models import CryptographicAssetRecord, CryptographicInventorySnapshot
from enterprise.crypto_lifecycle_models import CryptoLifecycleAssessment
from enterprise.models import Organization, OrganizationMembership, TenantProject

from .audit_writer import add_audit_entry


CRYPTO_LIFECYCLE_POLICY_VERSION = 'crypto-lifecycle-pqc.v1'
_POLICY = {
    'rotation_warning_days': 90,
    'rotation_urgent_days': 30,
    'pqc_target_kem': 'ML-KEM',
    'pqc_target_signature': 'ML-DSA',
    'pqc_fallback_signature': 'SLH-DSA',
    'hybrid_transition_allowed': True,
    'unknown_crypto_fail_closed': True,
}


class CryptoLifecycleError(ValueError):
    pass


class CryptoLifecycleAuthorizationError(CryptoLifecycleError):
    pass


@dataclass(frozen=True)
class CryptoLifecycleResult:
    assessment: CryptoLifecycleAssessment
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _active_context(*, snapshot_id: str, actor_id: str):
    snapshot_identity = (
        CryptographicInventorySnapshot.objects.filter(pk=snapshot_id)
        .values('id', 'organization_id', 'project_id', 'asset_id', 'authorization_decision_id')
        .first()
    )
    if snapshot_identity is None:
        raise CryptoLifecycleAuthorizationError('Cryptographic inventory snapshot was not found.')

    organization = (
        Organization.objects.select_for_update()
        .filter(pk=snapshot_identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        raise CryptoLifecycleAuthorizationError('Enterprise tenant is inactive.')

    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(
            organization_id=organization.id,
            project_id=snapshot_identity['project_id'],
        )
        .first()
    )
    if link is None:
        raise CryptoLifecycleAuthorizationError('Tenant/project binding changed before lifecycle evaluation.')

    project = Project.objects.select_for_update().filter(pk=snapshot_identity['project_id']).first()
    if project is None:
        raise CryptoLifecycleAuthorizationError('Project was not found.')

    project_allowed = str(project.owner_id) == str(actor_id) or ProjectMembership.objects.filter(
        project=project,
        user_id=actor_id,
        role__in=[
            ProjectMembership.Role.OWNER,
            ProjectMembership.Role.ADMIN,
            ProjectMembership.Role.MEMBER,
        ],
    ).exists()
    if not project_allowed:
        raise CryptoLifecycleAuthorizationError('Actor has no project access.')

    if not OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
    ).exists():
        raise CryptoLifecycleAuthorizationError('Actor has no active enterprise membership.')

    asset = Asset.objects.select_for_update().filter(
        pk=snapshot_identity['asset_id'],
        project=project,
    ).first()
    if asset is None:
        raise CryptoLifecycleAuthorizationError('Cryptographic asset lineage is no longer valid.')

    snapshot = (
        CryptographicInventorySnapshot.objects.select_for_update()
        .select_related('authorization_decision')
        .filter(pk=snapshot_id, project=project, asset=asset, organization=organization)
        .first()
    )
    if snapshot is None:
        raise CryptoLifecycleAuthorizationError('Cryptographic inventory lineage changed during evaluation.')

    latest_snapshot = (
        CryptographicInventorySnapshot.objects.select_for_update()
        .filter(project=project, asset=asset)
        .order_by('-snapshot_version', '-created_at', '-id')
        .first()
    )
    if latest_snapshot is None or latest_snapshot.id != snapshot.id:
        raise CryptoLifecycleAuthorizationError('Lifecycle evaluation requires the latest cryptographic inventory snapshot.')

    decision = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(pk=snapshot.authorization_decision_id, asset=asset)
        .first()
    )
    latest_decision = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(asset=asset)
        .order_by('-created_at', '-id')
        .first()
    )
    now = timezone.now()
    if (
        decision is None
        or latest_decision is None
        or latest_decision.id != decision.id
        or decision.authorized is not True
        or decision.valid_from > now
        or (decision.expires_at and decision.expires_at <= now)
    ):
        raise CryptoLifecycleAuthorizationError('Asset authorization decision is not currently admissible.')

    return organization, project, asset, snapshot


def _plan(records: list[CryptographicAssetRecord], now) -> tuple[dict[str, Any], dict[str, int], str, str]:
    urgent_cutoff = now + timedelta(days=int(_POLICY['rotation_urgent_days']))
    warning_cutoff = now + timedelta(days=int(_POLICY['rotation_warning_days']))

    weak_deprecated = 0
    expired = 0
    expiring_30 = 0
    expiring_90 = 0
    vulnerable = 0
    resistant = 0
    hybrid = 0
    unknown_quantum = 0

    actions: list[dict[str, Any]] = []
    for row in records:
        if row.security_state in {
            CryptographicAssetRecord.SecurityState.WEAK,
            CryptographicAssetRecord.SecurityState.DEPRECATED,
        }:
            weak_deprecated += 1
            actions.append({
                'priority': 'critical',
                'action': 'replace_deprecated_crypto',
                'record_fingerprint': row.fingerprint_sha256,
                'name': row.name,
                'algorithm': row.algorithm,
                'reason': row.security_state,
            })

        if row.security_state == CryptographicAssetRecord.SecurityState.EXPIRED:
            expired += 1
            actions.append({
                'priority': 'critical',
                'action': 'rotate_expired_material',
                'record_fingerprint': row.fingerprint_sha256,
                'name': row.name,
                'reason': 'expired',
            })
        elif row.not_after:
            if row.not_after <= urgent_cutoff:
                expiring_30 += 1
                actions.append({
                    'priority': 'high',
                    'action': 'rotate_before_expiry',
                    'record_fingerprint': row.fingerprint_sha256,
                    'name': row.name,
                    'due_at': row.not_after.isoformat(),
                })
            elif row.not_after <= warning_cutoff:
                expiring_90 += 1
                actions.append({
                    'priority': 'medium',
                    'action': 'schedule_rotation',
                    'record_fingerprint': row.fingerprint_sha256,
                    'name': row.name,
                    'due_at': row.not_after.isoformat(),
                })

        if row.quantum_state == CryptographicAssetRecord.QuantumState.VULNERABLE:
            vulnerable += 1
            actions.append({
                'priority': 'high',
                'action': 'migrate_to_pqc_or_hybrid',
                'record_fingerprint': row.fingerprint_sha256,
                'name': row.name,
                'algorithm': row.algorithm,
                'target_kem': _POLICY['pqc_target_kem'],
                'target_signature': _POLICY['pqc_target_signature'],
            })
        elif row.quantum_state == CryptographicAssetRecord.QuantumState.RESISTANT:
            resistant += 1
        elif row.quantum_state == CryptographicAssetRecord.QuantumState.HYBRID:
            hybrid += 1
        else:
            unknown_quantum += 1

    if expired or weak_deprecated:
        lifecycle_state = CryptoLifecycleAssessment.LifecycleState.CRITICAL
    elif expiring_30 or expiring_90 or vulnerable or unknown_quantum:
        lifecycle_state = CryptoLifecycleAssessment.LifecycleState.ACTION_REQUIRED
    else:
        lifecycle_state = CryptoLifecycleAssessment.LifecycleState.COMPLIANT

    if vulnerable:
        pqc_readiness = CryptoLifecycleAssessment.PQCReadiness.TRANSITION_REQUIRED
    elif hybrid:
        pqc_readiness = CryptoLifecycleAssessment.PQCReadiness.HYBRID
    elif resistant and not unknown_quantum:
        pqc_readiness = CryptoLifecycleAssessment.PQCReadiness.READY
    else:
        pqc_readiness = CryptoLifecycleAssessment.PQCReadiness.UNKNOWN

    priority_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    actions = sorted(
        actions,
        key=lambda item: (
            priority_rank.get(str(item.get('priority')), 9),
            str(item.get('record_fingerprint')),
            str(item.get('action')),
        ),
    )

    counts = {
        'total_records': len(records),
        'weak_deprecated_count': weak_deprecated,
        'expired_count': expired,
        'expiring_30d_count': expiring_30,
        'expiring_90d_count': expiring_90,
        'quantum_vulnerable_count': vulnerable,
        'quantum_resistant_count': resistant,
        'hybrid_count': hybrid,
        'unknown_quantum_count': unknown_quantum,
    }
    migration_plan = {
        'schema': 'aegis.crypto-migration-plan.v1',
        'policy_version': CRYPTO_LIFECYCLE_POLICY_VERSION,
        'target_profile': {
            'kem': _POLICY['pqc_target_kem'],
            'signature': _POLICY['pqc_target_signature'],
            'fallback_signature': _POLICY['pqc_fallback_signature'],
            'hybrid_transition_allowed': _POLICY['hybrid_transition_allowed'],
        },
        'summary': counts,
        'actions': actions,
    }
    return migration_plan, counts, lifecycle_state, pqc_readiness


@transaction.atomic
def evaluate_crypto_lifecycle(*, snapshot_id: str, actor_id: str) -> CryptoLifecycleResult:
    organization, project, asset, snapshot = _active_context(
        snapshot_id=str(snapshot_id),
        actor_id=str(actor_id),
    )
    records = list(
        CryptographicAssetRecord.objects.select_for_update()
        .filter(snapshot=snapshot)
        .order_by('ordinal', 'id')
    )
    if not records:
        raise CryptoLifecycleError('Cryptographic inventory snapshot contains no records.')

    policy_snapshot = dict(_POLICY)
    migration_plan, counts, lifecycle_state, pqc_readiness = _plan(records, timezone.now())
    assessment_projection = {
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'asset_id': str(asset.id),
        'snapshot_id': str(snapshot.id),
        'snapshot_version': int(snapshot.snapshot_version),
        'inventory_sha256': snapshot.inventory_sha256,
        'cbom_sha256': snapshot.cbom_sha256,
        'lifecycle_state': lifecycle_state,
        'pqc_readiness': pqc_readiness,
        'counts': counts,
        'policy_snapshot': policy_snapshot,
        'migration_plan': migration_plan,
        'policy_version': CRYPTO_LIFECYCLE_POLICY_VERSION,
    }
    assessment_sha256 = _sha(assessment_projection)
    request_fingerprint = _sha({
        'snapshot_id': str(snapshot.id),
        'inventory_sha256': snapshot.inventory_sha256,
        'assessment_sha256': assessment_sha256,
        'policy_version': CRYPTO_LIFECYCLE_POLICY_VERSION,
    })

    replay = CryptoLifecycleAssessment.objects.filter(request_fingerprint=request_fingerprint).first()
    if replay is not None:
        return CryptoLifecycleResult(assessment=replay, replayed=True)

    previous = (
        CryptoLifecycleAssessment.objects.select_for_update()
        .filter(project=project, asset=asset)
        .order_by('-assessment_version', '-created_at', '-id')
        .first()
    )
    next_version = int(previous.assessment_version) + 1 if previous else 1

    assessment = CryptoLifecycleAssessment.objects.create(
        organization=organization,
        project=project,
        asset=asset,
        inventory_snapshot=snapshot,
        predecessor=previous,
        evaluated_by_id=actor_id,
        assessment_version=next_version,
        lifecycle_state=lifecycle_state,
        pqc_readiness=pqc_readiness,
        total_records=counts['total_records'],
        weak_deprecated_count=counts['weak_deprecated_count'],
        expired_count=counts['expired_count'],
        expiring_30d_count=counts['expiring_30d_count'],
        expiring_90d_count=counts['expiring_90d_count'],
        quantum_vulnerable_count=counts['quantum_vulnerable_count'],
        quantum_resistant_count=counts['quantum_resistant_count'],
        hybrid_count=counts['hybrid_count'],
        policy_snapshot=policy_snapshot,
        migration_plan=migration_plan,
        assessment_sha256=assessment_sha256,
        request_fingerprint=request_fingerprint,
        policy_version=CRYPTO_LIFECYCLE_POLICY_VERSION,
    )

    add_audit_entry(
        user=str(actor_id),
        action='crypto_lifecycle.evaluate',
        target=str(assessment.id),
        project=str(project.id),
        resource_type='crypto_lifecycle_assessment',
        resource_repr=f'{asset.id}:v{next_version}',
        metadata={
            'organization_id': str(organization.id),
            'asset_id': str(asset.id),
            'snapshot_id': str(snapshot.id),
            'snapshot_version': int(snapshot.snapshot_version),
            'authorization_decision_id': str(snapshot.authorization_decision_id),
            'lifecycle_state': lifecycle_state,
            'pqc_readiness': pqc_readiness,
            'assessment_sha256': assessment_sha256,
            'policy_version': CRYPTO_LIFECYCLE_POLICY_VERSION,
        },
    )
    return CryptoLifecycleResult(assessment=assessment, replayed=False)
