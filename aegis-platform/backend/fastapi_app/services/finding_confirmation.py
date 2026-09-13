from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from django.db import transaction

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.evidence.models import Evidence, FindingConfirmation, ValidationRun
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory

from .audit_writer import add_audit_entry
from .authorization_guard import asset_target, require_bound_validation_authorization


POLICY_VERSION = 'finding-confirmation.v1'


class FindingConfirmationError(ValueError):
    pass


@dataclass(frozen=True)
class ConfirmationResult:
    confirmation: FindingConfirmation
    replayed: bool
    status_changed: bool
    previous_status: str


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    ).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _normalize_rationale(value: str) -> str:
    return ' '.join(str(value or '').strip().split())


def _request_fingerprint(validation_id: UUID | str, verdict: str, rationale: str) -> str:
    return _canonical_digest({
        'validation_id': str(validation_id),
        'verdict': verdict,
        'rationale': _normalize_rationale(rationale),
        'policy_version': POLICY_VERSION,
    })


def _expected_presence(verdict: str) -> bool:
    if verdict == FindingConfirmation.Verdict.CONFIRMED:
        return True
    if verdict == FindingConfirmation.Verdict.FALSE_POSITIVE:
        return False
    raise FindingConfirmationError(f'Unsupported confirmation verdict: {verdict}')


def _validate_state(finding: Vulnerability, verdict: str) -> None:
    if verdict == FindingConfirmation.Verdict.CONFIRMED:
        if finding.status not in {Vulnerability.Status.OPEN, Vulnerability.Status.CONFIRMED}:
            raise FindingConfirmationError(
                f'Finding status {finding.status} cannot transition to confirmed through evidence confirmation.'
            )
        return
    if verdict == FindingConfirmation.Verdict.FALSE_POSITIVE:
        if finding.status != Vulnerability.Status.OPEN:
            raise FindingConfirmationError(
                'False-positive classification is only allowed for an open finding; '
                'remediated or previously governed findings cannot be reclassified as false positives.'
            )
        return
    raise FindingConfirmationError(f'Unsupported confirmation verdict: {verdict}')


def _validate_preflight_authorization(validation: ValidationRun) -> AssetAuthorization:
    _asset, reason, decision = require_bound_validation_authorization(validation)
    if decision is None:
        raise FindingConfirmationError(reason)
    return decision


def _locked_authorization_is_still_current(
    finding: Vulnerability,
    validation: ValidationRun,
    preflight_decision: AssetAuthorization,
) -> AssetAuthorization:
    if not finding.asset_id:
        raise FindingConfirmationError('Finding confirmation requires a persisted asset.')
    asset = Asset.objects.select_for_update().get(pk=finding.asset_id)
    decision = AssetAuthorization.objects.select_for_update().get(pk=validation.authorization_decision_id)
    latest = (
        AssetAuthorization.objects.select_for_update()
        .filter(asset=asset)
        .order_by('-created_at', '-id')
        .first()
    )
    if decision.id != preflight_decision.id:
        raise FindingConfirmationError('Bound authorization changed after confirmation preflight.')
    if latest is None or latest.id != decision.id:
        raise FindingConfirmationError('Bound authorization is no longer the latest asset decision.')
    if decision.authorized is not True or not decision.is_currently_valid:
        raise FindingConfirmationError('Bound authorization is no longer valid at confirmation commit.')
    if decision.asset_identity_snapshot != asset.id:
        raise FindingConfirmationError('Authorization decision is not bound to the current asset identity.')
    if asset_target(asset) != str(decision.target_snapshot or '').strip():
        raise FindingConfirmationError('Asset target changed after validation; confirmation is not trusted.')
    if str(validation.target_value or '').strip() != str(decision.target_snapshot or '').strip():
        raise FindingConfirmationError('Validation target no longer matches the authorization snapshot.')
    return decision


def _resolve_evidence(validation: ValidationRun, finding: Vulnerability) -> Evidence:
    result = validation.result if isinstance(validation.result, dict) else {}
    evidence_id = result.get('evidence_id')
    if not evidence_id:
        raise FindingConfirmationError('Completed validation result has no evidence_id.')
    evidence = Evidence.objects.select_for_update().filter(pk=evidence_id, finding=finding).first()
    if evidence is None:
        raise FindingConfirmationError('Validation evidence is missing or belongs to a different finding.')
    if evidence.evidence_type != 'validation_output':
        raise FindingConfirmationError('Finding confirmation requires validation_output evidence.')

    metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
    metadata_validation_id = metadata.get('validation_run_id') or metadata.get('validation_id')
    if str(metadata_validation_id or '') != str(validation.id):
        raise FindingConfirmationError('Evidence is not bound to the requested validation run.')
    if metadata.get('finding_present') != result.get('finding_present'):
        raise FindingConfirmationError('Evidence finding_present does not match the validation result.')
    if str(metadata.get('authorization_decision_id') or '') != str(validation.authorization_decision_id):
        raise FindingConfirmationError('Evidence authorization lineage does not match the validation run.')
    return evidence


def confirm_finding(
    *,
    finding_id: UUID | str,
    validation_id: UUID | str,
    verdict: str,
    rationale: str,
    actor_id: UUID | str,
) -> ConfirmationResult:
    normalized_rationale = _normalize_rationale(rationale)
    fingerprint = _request_fingerprint(validation_id, verdict, normalized_rationale)

    validation = (
        ValidationRun.objects.select_related('finding', 'finding__asset', 'authorization_decision')
        .filter(pk=validation_id, finding_id=finding_id)
        .first()
    )
    if validation is None:
        raise FindingConfirmationError('Validation run was not found for this finding.')
    if validation.status != ValidationRun.Status.COMPLETED or validation.authorized is not True:
        raise FindingConfirmationError('Finding confirmation requires a completed authorized validation run.')
    if not validation.authorization_decision_id:
        raise FindingConfirmationError('Validation run has no bound authorization decision.')
    preflight_decision = _validate_preflight_authorization(validation)

    with transaction.atomic():
        finding = (
            Vulnerability.objects.select_for_update()
            .select_related('asset', 'project')
            .get(pk=finding_id)
        )
        validation = (
            ValidationRun.objects.select_for_update()
            .select_related('authorization_decision')
            .get(pk=validation_id, finding=finding)
        )

        existing = FindingConfirmation.objects.select_for_update().filter(validation_run=validation).first()
        if existing is not None:
            if existing.request_fingerprint != fingerprint or existing.verdict != verdict:
                raise FindingConfirmationError(
                    'This validation run already has an immutable confirmation with different semantics.'
                )
            return ConfirmationResult(
                confirmation=existing,
                replayed=True,
                status_changed=False,
                previous_status=finding.status,
            )

        if validation.status != ValidationRun.Status.COMPLETED or validation.authorized is not True:
            raise FindingConfirmationError('Validation state changed before confirmation commit.')
        if not validation.authorization_decision_id:
            raise FindingConfirmationError('Validation lost its authorization binding before confirmation commit.')
        decision = _locked_authorization_is_still_current(finding, validation, preflight_decision)

        result = validation.result if isinstance(validation.result, dict) else {}
        finding_present = result.get('finding_present')
        if not isinstance(finding_present, bool):
            raise FindingConfirmationError('Validation result does not contain a boolean finding_present verdict.')
        expected_presence = _expected_presence(verdict)
        if finding_present is not expected_presence:
            raise FindingConfirmationError(
                f'Confirmation verdict {verdict} conflicts with validation finding_present={finding_present}.'
            )

        _validate_state(finding, verdict)
        evidence = _resolve_evidence(validation, finding)
        result_sha256 = _canonical_digest(result)
        metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
        engine = str(result.get('tool') or evidence.source or '').strip().lower()

        confirmation = FindingConfirmation.objects.create(
            finding=finding,
            validation_run=validation,
            evidence=evidence,
            authorization_decision=decision,
            created_by_id=actor_id,
            verdict=verdict,
            finding_present=finding_present,
            policy_version=POLICY_VERSION,
            evidence_sha256=evidence.sha256,
            result_sha256=result_sha256,
            request_fingerprint=fingerprint,
            rationale=normalized_rationale,
            metadata={
                'engine': engine,
                'evidence_type': evidence.evidence_type,
                'validation_run_id': str(validation.id),
                'authorization_decision_id': str(decision.id),
                'finding_present': finding_present,
                'validation_evidence_format': metadata.get('format'),
            },
        )

        previous_status = finding.status
        now = datetime.now(timezone.utc)
        if verdict == FindingConfirmation.Verdict.CONFIRMED:
            finding.status = Vulnerability.Status.CONFIRMED
            finding.confidence = Vulnerability.Confidence.CONFIRMED
            finding.validation_status = 'confirmed'
        else:
            finding.status = Vulnerability.Status.FALSE_POSITIVE
            finding.validation_status = 'false_positive'
        finding.validated_at = validation.completed_at or now
        finding.validated_by_id = actor_id
        finding.evidence_count = finding.evidence_records.count()
        finding.save(update_fields=[
            'status', 'confidence', 'validation_status', 'validated_at', 'validated_by',
            'evidence_count', 'updated_at',
        ])

        status_changed = previous_status != finding.status
        if status_changed:
            VulnerabilityStatusHistory.objects.create(
                vulnerability=finding,
                old_status=previous_status,
                new_status=finding.status,
                changed_by_id=actor_id,
                reason=(
                    f'Governed finding confirmation {confirmation.id}; '
                    f'validation={validation.id}; evidence_sha256={evidence.sha256}'
                ),
            )

        add_audit_entry(
            user=str(actor_id),
            action=AuditLog.Action.VULN_STATUS_CHANGE,
            target=str(finding.id),
            project=str(finding.project_id),
            resource_type='vulnerability',
            resource_repr=f'Governed finding confirmation {confirmation.id}',
            changes={
                'status': {'from': previous_status, 'to': finding.status},
                'validation_status': finding.validation_status,
            },
            metadata={
                'operation': 'finding_confirmation',
                'confirmation_id': str(confirmation.id),
                'validation_id': str(validation.id),
                'evidence_id': str(evidence.id),
                'authorization_decision_id': str(decision.id),
                'evidence_sha256': evidence.sha256,
                'result_sha256': result_sha256,
                'verdict': verdict,
                'finding_present': finding_present,
                'policy_version': POLICY_VERSION,
            },
        )

        return ConfirmationResult(
            confirmation=confirmation,
            replayed=False,
            status_changed=status_changed,
            previous_status=previous_status,
        )


def list_confirmations(*, finding_id: UUID | str) -> list[FindingConfirmation]:
    return list(
        FindingConfirmation.objects.filter(finding_id=finding_id)
        .select_related('validation_run', 'evidence', 'authorization_decision', 'created_by')
        .order_by('-created_at')
    )
