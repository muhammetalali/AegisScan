from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from django.db import transaction

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.evidence.models import Evidence, ValidationRun
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory

from .audit_writer import add_audit_entry
from .authorization_guard import asset_target
from .remediation_lifecycle import RemediationState, get_state


POLICY_VERSION = 'finding-closure.v1'


class FindingClosureError(ValueError):
    pass


class StaleFindingClosureVersion(FindingClosureError):
    pass


@dataclass(frozen=True)
class FindingClosureResult:
    finding: Vulnerability
    validation: ValidationRun
    evidence: Evidence
    previous_status: str


def _latest_validation_locked(finding: Vulnerability) -> ValidationRun:
    validation = (
        ValidationRun.objects.select_for_update(of=('self',))
        .filter(finding=finding)
        .order_by('-created_at', '-id')
        .first()
    )
    if validation is None:
        raise FindingClosureError('Finding closure requires a finding-linked validation run.')
    return validation


def _resolve_verified_evidence(validation: ValidationRun, finding: Vulnerability) -> Evidence:
    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is not False:
        raise FindingClosureError('Finding closure requires remediation evidence showing finding absence.')
    evidence_id = result.get('evidence_id')
    if not evidence_id:
        raise FindingClosureError('Verified remediation validation has no evidence_id.')
    evidence = (
        Evidence.objects.select_for_update(of=('self',))
        .filter(pk=evidence_id, finding=finding)
        .first()
    )
    if evidence is None:
        raise FindingClosureError('Remediation evidence is missing or belongs to a different finding.')
    expected_sha = hashlib.sha256(evidence.raw_output.encode('utf-8', errors='replace')).hexdigest()
    if expected_sha != evidence.sha256:
        raise FindingClosureError('Remediation evidence SHA-256 integrity verification failed.')
    metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
    metadata_validation_id = metadata.get('validation_run_id') or metadata.get('validation_id')
    if str(metadata_validation_id or '') != str(validation.id):
        raise FindingClosureError('Remediation evidence is not bound to the latest validation run.')
    if str(metadata.get('authorization_decision_id') or '') != str(validation.authorization_decision_id or ''):
        raise FindingClosureError('Remediation evidence authorization lineage does not match the validation run.')
    return evidence


def _lock_current_authorization(finding: Vulnerability, validation: ValidationRun) -> AssetAuthorization:
    if not finding.asset_id:
        raise FindingClosureError('Finding closure requires a persisted asset.')
    if not validation.authorization_decision_id:
        raise FindingClosureError('Verified validation has no bound authorization decision.')
    asset = Asset.objects.select_for_update(of=('self',)).get(pk=finding.asset_id)
    decision = AssetAuthorization.objects.select_for_update(of=('self',)).get(pk=validation.authorization_decision_id)
    latest = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(asset=asset)
        .order_by('-created_at', '-id')
        .first()
    )
    if latest is None or latest.id != decision.id:
        raise FindingClosureError('Validation authorization is no longer the latest asset decision.')
    if decision.authorized is not True or not decision.is_currently_valid:
        raise FindingClosureError('Validation authorization is no longer valid at closure commit.')
    if decision.asset_identity_snapshot != asset.id:
        raise FindingClosureError('Authorization decision is not bound to the current asset identity.')
    target = asset_target(asset)
    if target != str(decision.target_snapshot or '').strip():
        raise FindingClosureError('Asset target changed after remediation verification.')
    if str(validation.target_value or '').strip() != str(decision.target_snapshot or '').strip():
        raise FindingClosureError('Validation target no longer matches the authorization snapshot.')
    return decision


def close_finding(
    *,
    finding_id: UUID | str,
    actor_id: UUID | str,
    expected_version: int,
    emit_audit: bool = True,
) -> FindingClosureResult:
    with transaction.atomic():
        finding = Vulnerability.objects.select_for_update(of=('self',)).get(pk=finding_id)
        if int(finding.version) != int(expected_version):
            raise StaleFindingClosureVersion(
                f'Expected finding version {expected_version}, current version is {finding.version}.'
            )
        if finding.status not in {Vulnerability.Status.CONFIRMED, Vulnerability.Status.IN_PROGRESS}:
            raise FindingClosureError(
                f'Finding status {finding.status} is not eligible for governed remediation closure.'
            )

        validation = _latest_validation_locked(finding)
        if validation.status != ValidationRun.Status.COMPLETED or validation.authorized is not True:
            raise FindingClosureError('Finding closure requires the latest completed authorized validation.')
        if get_state(validation) != RemediationState.VERIFIED:
            raise FindingClosureError('Finding closure requires the latest remediation validation to be VERIFIED.')
        if str(validation.user_id) == str(actor_id):
            raise FindingClosureError('Closure actor must be independent from the remediation verifier.')

        evidence = _resolve_verified_evidence(validation, finding)
        decision = _lock_current_authorization(finding, validation)
        previous_status = finding.status
        now = datetime.now(timezone.utc)

        result: dict[str, Any] = dict(validation.result) if isinstance(validation.result, dict) else {}
        history = result.get('remediation_events')
        if not isinstance(history, list):
            history = []
        history.append({
            'from': RemediationState.VERIFIED,
            'to': RemediationState.CLOSED,
            'at': now.isoformat(),
            'reason': 'Independent governed finding closure approved.',
            'evidence_id': str(evidence.id),
            'user_id': str(actor_id),
        })
        result['remediation_state'] = RemediationState.CLOSED
        result['remediation_events'] = history
        validation.result = result
        validation.save(update_fields=['result'])

        finding.status = Vulnerability.Status.FIXED
        finding.validation_status = 'closed'
        finding.fixed_at = now
        finding.fixed_by_id = actor_id
        finding.version = int(finding.version) + 1
        finding.save(update_fields=[
            'status', 'validation_status', 'fixed_at', 'fixed_by', 'version', 'updated_at',
        ])
        VulnerabilityStatusHistory.objects.create(
            vulnerability=finding,
            old_status=previous_status,
            new_status=finding.status,
            changed_by_id=actor_id,
            reason=(
                f'Governed independent closure; validation={validation.id}; '
                f'evidence={evidence.id}; authorization={decision.id}; evidence_sha256={evidence.sha256}'
            ),
        )

        if emit_audit:
            add_audit_entry(
                user=str(actor_id),
                action=AuditLog.Action.VULN_STATUS_CHANGE,
                target=str(finding.id),
                project=str(finding.project_id),
                resource_type='vulnerability',
                resource_repr=f'Governed finding closure {finding.id}',
                changes={
                    'status': {'from': previous_status, 'to': finding.status},
                    'validation_status': finding.validation_status,
                    'version': {'from': finding.version - 1, 'to': finding.version},
                },
                metadata={
                    'operation': 'finding_closure',
                    'validation_id': str(validation.id),
                    'evidence_id': str(evidence.id),
                    'authorization_decision_id': str(decision.id),
                    'evidence_sha256': evidence.sha256,
                    'policy_version': POLICY_VERSION,
                },
            )

        return FindingClosureResult(
            finding=finding,
            validation=validation,
            evidence=evidence,
            previous_status=previous_status,
        )
