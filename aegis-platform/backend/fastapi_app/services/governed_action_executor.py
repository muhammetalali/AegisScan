from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Callable

from django.db import transaction

from django_project.audit.models import AuditLog
from django_project.audit.services import append_audit
from django_project.evidence.models import FindingDisposition, ValidationRun
from django_project.vulnerabilities.models import Vulnerability
from enterprise.governed_action_models import GovernedActionExecution, GovernedActionRequest
from enterprise.models import Organization, TenantProject
from fastapi_app.contracts.governed_operations import AGOM_CONTRACT_VERSION, ActionMode
from fastapi_app.services.asset_authorization_governance import govern_asset_authorization
from fastapi_app.services.campaign_objective_assurance import assess_objective, complete_campaign
from fastapi_app.services.finding_closure import close_finding
from fastapi_app.services.finding_disposition import govern_finding_disposition
from fastapi_app.services.finding_confirmation import confirm_finding
from fastapi_app.services.evidence_qualification import EvidenceQualificationPolicy, qualify_evidence
from fastapi_app.services.detection_engineering import DetectionEngineeringError, queue_publication_delivery
from fastapi_app.services.governed_capability_manifest import build_governed_capability_manifest
from fastapi_app.services.integration_live_acceptance import (
    IntegrationAcceptanceConflict,
    IntegrationAcceptanceError,
    accept_integration_live,
)
from fastapi_app.services.governed_temporal_policy import (
    TemporalEnvelope,
    evaluate_governed_temporal_policy,
)
from fastapi_app.services.governed_operations import get_action_contract
from fastapi_app.services.soc_closure_governance import close_investigation_case


_INVESTIGATION_REMEDIATION_EVIDENCE_POLICY = EvidenceQualificationPolicy(
    policy_version='investigation-remediation-evidence.v2',
    min_count=1,
    evidence_types=('validation_output',),
    require_subject=True,
    require_target=True,
    require_authorization=True,
    require_execution=True,
    require_producer=True,
)


_FINDING_CONFIRM_EVIDENCE_POLICY = EvidenceQualificationPolicy(
    policy_version='finding-confirmation-evidence.v1',
    min_count=1,
    evidence_types=('validation_output',),
    require_subject=True,
    require_target=True,
    require_authorization=True,
    require_execution=True,
    require_producer=True,
)


_IMPLEMENTED_ACTIONS = {
    'asset.authorization.approve',
    'asset.authorization.revoke',
    'campaign.objective.assess',
    'campaign.complete',
    'detection.publish',
    'finding.confirm',
    'finding.false_positive',
    'finding.disposition.accept_risk',
    'finding.disposition.wont_fix',
    'finding.disposition.duplicate',
    'finding.close',
    'investigation.close',
    'integration.live_accept',
}

_REQUEST_REQUIRED_ACTIONS = {
    'asset.authorization.approve',
    'asset.authorization.revoke',
    'detection.publish',
    'finding.false_positive',
    'finding.disposition.accept_risk',
    'finding.disposition.wont_fix',
    'finding.disposition.duplicate',
    'investigation.close',
    'integration.live_accept',
}


class GovernedActionError(ValueError):
    pass


class GovernedActionConflict(GovernedActionError):
    pass


class GovernedActionBlocked(GovernedActionError):
    def __init__(self, reason_code: str, reason: str, missing_requirements: list[str] | None = None):
        super().__init__(reason)
        self.reason_code = str(reason_code or 'ACTION_BLOCKED')
        self.reason = str(reason or 'Governed action is blocked.')
        self.missing_requirements = list(missing_requirements or [])


@dataclass(frozen=True)
class GovernedActionResult:
    execution: GovernedActionExecution
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _normalize_idempotency_key(value: str) -> str:
    key = str(value or '').strip()
    if not key:
        raise GovernedActionError('A non-empty idempotency_key is required.')
    if len(key) > 128:
        raise GovernedActionError('idempotency_key exceeds 128 characters.')
    return key


def _project_scope(project_id: str) -> tuple[str, Any]:
    row = (
        TenantProject.objects.select_related('project')
        .filter(project_id=project_id, organization__is_active=True)
        .first()
    )
    if row is None:
        raise GovernedActionError('Governed action project scope was not found.')
    return str(row.organization_id), row.project


def _projection_dict(manifest) -> dict[str, Any]:
    return manifest.projection.model_dump(mode='json')


def _capability_for(manifest, action_id: str):
    matches = [item for item in manifest.capabilities if item.action_id == action_id]
    if len(matches) != 1:
        raise GovernedActionError('Authoritative capability manifest does not contain exactly one requested action capability.')
    return matches[0]


def _require_parameters(parameters: dict[str, Any], *, required: set[str], allowed: set[str]) -> None:
    extras = sorted(set(parameters) - allowed)
    missing = sorted(key for key in required if key not in parameters or parameters[key] in (None, ''))
    if extras:
        raise GovernedActionError(f'Unsupported governed action parameters: {extras}.')
    if missing:
        raise GovernedActionError(f'Missing governed action parameters: {missing}.')


def _qualification_view(result) -> dict[str, Any]:
    evaluation = result.evaluation
    return {
        'evaluation_id': str(evaluation.id),
        'decision': evaluation.decision,
        'qualified': bool(evaluation.qualified),
        'reason_codes': list(evaluation.reason_codes or []),
        'policy_version': evaluation.policy_version,
        'evidence_set_hash': evaluation.evidence_set_hash,
        'evaluation_fingerprint': evaluation.evaluation_fingerprint,
        'evaluated_at': evaluation.evaluated_at.isoformat(),
        'replayed': bool(result.replayed),
    }


def _temporal_view(result) -> dict[str, Any]:
    evaluation = result.evaluation
    return {
        'evaluation_id': str(evaluation.id),
        'decision': evaluation.decision,
        'allowed': bool(evaluation.allowed),
        'reason_codes': list(evaluation.reason_codes or []),
        'policy_version': evaluation.policy_version,
        'effective_from': evaluation.effective_from.isoformat() if evaluation.effective_from else None,
        'expires_at': evaluation.expires_at.isoformat() if evaluation.expires_at else None,
        'review_at': evaluation.review_at.isoformat() if evaluation.review_at else None,
        'grace_period_seconds': int(evaluation.grace_period_seconds),
        'escalation_level': int(evaluation.escalation_level),
        'exception_id': str(evaluation.exception_id) if evaluation.exception_id else None,
        'evaluation_fingerprint': evaluation.evaluation_fingerprint,
        'evaluated_at': evaluation.evaluated_at.isoformat(),
        'replayed': bool(result.replayed),
    }


def _temporal_envelope_for_action(
    *,
    action_id: str,
    entity_id: str,
    parameters: dict[str, Any],
) -> TemporalEnvelope:
    if action_id == 'asset.authorization.approve':
        expires_raw = parameters.get('expires_at')
        expires_at = None
        if expires_raw:
            try:
                expires_at = (
                    expires_raw if isinstance(expires_raw, datetime)
                    else datetime.fromisoformat(str(expires_raw).replace('Z', '+00:00'))
                )
            except ValueError:
                expires_at = None
        return TemporalEnvelope(
            expires_at=expires_at,
            recurrence={
                'source': 'asset_authorization_request',
                'asset_id': str(entity_id),
            },
        )

    if action_id == 'integration.live_accept':
        review_raw = parameters.get('review_at')
        expires_raw = parameters.get('expires_at')
        review_at = review_raw if isinstance(review_raw, datetime) else None
        expires_at = expires_raw if isinstance(expires_raw, datetime) else None
        if review_at is None and review_raw:
            try:
                review_at = datetime.fromisoformat(str(review_raw).replace('Z', '+00:00'))
            except ValueError:
                review_at = None
        if expires_at is None and expires_raw:
            try:
                expires_at = datetime.fromisoformat(str(expires_raw).replace('Z', '+00:00'))
            except ValueError:
                expires_at = None
        return TemporalEnvelope(
            review_at=review_at,
            expires_at=expires_at,
            recurrence={
                'source': 'integration_live_acceptance',
                'integration_id': str(entity_id),
                'acceptance_test_id': str(parameters.get('acceptance_test_id') or ''),
            },
        )

    validation = None
    if action_id in {'finding.confirm', 'finding.false_positive'}:
        validation_id = str(parameters.get('validation_id') or '').strip()
        if validation_id:
            validation = (
                ValidationRun.objects.select_related('authorization_decision')
                .filter(pk=validation_id, finding_id=entity_id)
                .first()
            )
    elif action_id == 'finding.close':
        validation = (
            ValidationRun.objects.select_related('authorization_decision')
            .filter(finding_id=entity_id)
            .order_by('-created_at', '-id')
            .first()
        )
    if action_id in {'finding.disposition.accept_risk', 'finding.disposition.wont_fix'}:
        review_raw = parameters.get('review_at')
        review_at = review_raw if isinstance(review_raw, datetime) else None
        if review_at is None and review_raw:
            try:
                review_at = datetime.fromisoformat(str(review_raw).replace('Z', '+00:00'))
            except ValueError:
                review_at = None
        return TemporalEnvelope(
            review_at=review_at,
            recurrence={
                'source': 'finding_disposition_review',
                'finding_id': str(entity_id),
            },
        )

    decision = validation.authorization_decision if validation is not None else None
    if decision is None:
        return TemporalEnvelope()
    return TemporalEnvelope(
        effective_from=decision.valid_from,
        expires_at=decision.expires_at,
        renewal_ref=str(decision.id),
        recurrence={
            'source': 'asset_authorization',
            'authorization_decision_id': str(decision.id),
        },
    )


def _preflight_temporal_policy(
    *,
    action_id: str,
    project_id: str,
    actor_id: str,
    entity_type: str,
    entity_id: str,
    parameters: dict[str, Any],
    evaluated_at=None,
    request_proposer_id: str = '',
):
    manifest = build_governed_capability_manifest(
        project_id=project_id,
        user_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        request_proposer_id=request_proposer_id,
        execution_parameters=parameters if request_proposer_id else None,
    )
    capability = _capability_for(manifest, action_id)
    if capability.mode is ActionMode.HIDDEN:
        raise PermissionError('Governed action is not available to this actor.')
    if capability.mode is not ActionMode.ENABLED:
        raise GovernedActionBlocked(
            capability.reason_code,
            capability.reason,
            capability.missing_requirements,
        )
    result = evaluate_governed_temporal_policy(
        project_id=project_id,
        action_id=action_id,
        entity_type=entity_type,
        entity_id=entity_id,
        requested_by_id=actor_id,
        envelope=_temporal_envelope_for_action(
            action_id=action_id,
            entity_id=entity_id,
            parameters=parameters,
        ),
        evaluated_at=evaluated_at,
    )
    if not result.allowed:
        evaluation = result.evaluation
        raise GovernedActionBlocked(
            'TEMPORAL_POLICY_BLOCKED',
            f'Governed temporal policy rejected the action: {evaluation.decision}.',
            list(evaluation.reason_codes or [evaluation.decision]),
        )
    return result


def _finding_confirmation_qualification(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    parameters: dict[str, Any],
    evaluated_at=None,
):
    validation_id = str(parameters.get('validation_id') or '').strip()
    if not validation_id:
        return None
    validation = (
        ValidationRun.objects.select_related('finding', 'authorization_decision')
        .filter(pk=validation_id, finding_id=entity_id)
        .first()
    )
    if validation is None:
        return None
    result = validation.result if isinstance(validation.result, dict) else {}
    evidence_id = str(result.get('evidence_id') or '').strip()
    if not evidence_id:
        return None
    return qualify_evidence(
        project_id=project_id,
        evidence_ids=[evidence_id],
        subject_type='finding',
        subject_id=entity_id,
        target=str(validation.target_value or ''),
        authorization_ref=str(validation.authorization_decision_id or ''),
        execution_ref=str(validation.id),
        requested_by_id=actor_id,
        policy=_FINDING_CONFIRM_EVIDENCE_POLICY,
        evaluated_at=evaluated_at,
    )


def _investigation_closure_qualification(
    *,
    project_id: str,
    actor_id: str,
    case_id: str,
    parameters: dict[str, Any],
    evaluated_at=None,
):
    if str(parameters.get('closure_type') or '').strip() != 'remediated':
        return None
    finding_id = str(parameters.get('finding_id') or '').strip()
    validation_id = str(parameters.get('validation_id') or '').strip()
    if not finding_id or not validation_id:
        return None
    validation = (
        ValidationRun.objects.select_related('finding', 'authorization_decision')
        .filter(pk=validation_id, finding_id=finding_id, finding__project_id=project_id)
        .first()
    )
    if validation is None:
        return None
    latest = (
        ValidationRun.objects.filter(finding_id=finding_id)
        .order_by('-created_at', '-id')
        .values_list('id', flat=True)
        .first()
    )
    if latest is None or str(latest) != str(validation.id):
        raise GovernedActionBlocked(
            'LATEST_REMEDIATION_VALIDATION_REQUIRED',
            'Investigation closure must bind the latest validation for the governed finding.',
            ['latest_remediation_validation'],
        )
    result = validation.result if isinstance(validation.result, dict) else {}
    if validation.status != ValidationRun.Status.COMPLETED or validation.authorized is not True:
        return None
    if result.get('finding_present') is not False:
        return None
    evidence_id = str(result.get('evidence_id') or '').strip()
    if not evidence_id:
        return None
    return qualify_evidence(
        project_id=project_id,
        evidence_ids=[evidence_id],
        subject_type='finding',
        subject_id=finding_id,
        target=str(validation.target_value or ''),
        authorization_ref=str(validation.authorization_decision_id or ''),
        execution_ref=str(validation.id),
        requested_by_id=actor_id,
        policy=_INVESTIGATION_REMEDIATION_EVIDENCE_POLICY,
        evaluated_at=evaluated_at,
    )


def _require_qualified_evidence(result) -> None:
    if result is None:
        raise GovernedActionBlocked(
            'EVIDENCE_QUALIFICATION_REQUIRED',
            'Evidence qualification could not resolve the governed action evidence set.',
            ['qualified_evidence'],
        )
    if not result.qualified:
        evaluation = result.evaluation
        raise GovernedActionBlocked(
            'EVIDENCE_NOT_QUALIFIED',
            f'Evidence qualification rejected: {evaluation.decision}.',
            list(evaluation.reason_codes or [evaluation.decision]),
        )


def _preflight_evidence_qualification(
    *,
    action_id: str,
    project_id: str,
    actor_id: str,
    entity_type: str,
    entity_id: str,
    parameters: dict[str, Any],
    request_proposer_id: str = '',
):
    if action_id not in {'finding.confirm', 'finding.false_positive', 'investigation.close'}:
        return None
    manifest = build_governed_capability_manifest(
        project_id=project_id,
        user_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        request_proposer_id=request_proposer_id,
        execution_parameters=parameters if request_proposer_id else None,
    )
    capability = _capability_for(manifest, action_id)
    if capability.mode is ActionMode.HIDDEN:
        raise PermissionError('Governed action is not available to this actor.')
    if capability.mode is not ActionMode.ENABLED:
        raise GovernedActionBlocked(
            capability.reason_code,
            capability.reason,
            capability.missing_requirements,
        )
    if action_id == 'investigation.close':
        result = _investigation_closure_qualification(
            project_id=project_id,
            actor_id=actor_id,
            case_id=entity_id,
            parameters=parameters,
        )
        if str(parameters.get('closure_type') or '').strip() == 'remediated':
            _require_qualified_evidence(result)
        return result
    result = _finding_confirmation_qualification(
        project_id=project_id,
        actor_id=actor_id,
        entity_id=entity_id,
        parameters=parameters,
    )
    _require_qualified_evidence(result)
    return result


def _bound_governed_request(
    *,
    request_id: str,
    organization_id: str,
    project_id: str,
    action_id: str,
    entity_type: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
    actor_id: str,
    lock: bool,
) -> GovernedActionRequest:
    queryset = GovernedActionRequest.objects
    if lock:
        queryset = queryset.select_for_update(of=('self',))
    row = queryset.filter(
        pk=request_id,
        organization_id=organization_id,
        project_id=project_id,
    ).first()
    if row is None:
        raise GovernedActionError('Governed action request was not found in the locked tenant/project scope.')
    expected = {
        'action_id': action_id,
        'entity_type': entity_type,
        'entity_id': entity_id,
        'expected_version': int(expected_version),
    }
    observed = {
        'action_id': row.action_id,
        'entity_type': row.entity_type,
        'entity_id': row.entity_id,
        'expected_version': int(row.expected_version),
    }
    if observed != expected or dict(row.parameters_snapshot or {}) != dict(parameters or {}):
        raise GovernedActionConflict('Governed action request does not match the execution command.')
    consumed = GovernedActionExecution.objects.filter(request=row).first()
    if consumed is not None:
        raise GovernedActionConflict('Governed action request has already been consumed by an immutable execution.')
    return row


def _execute_objective_assessment(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    allowed = {
        'campaign_id',
        'attack_path_id',
        'evidence_id',
        'outcome',
        'reason_code',
        'explanation',
        'blast_radius_snapshot_id',
        'validation_id',
    }
    required = {'campaign_id', 'attack_path_id', 'evidence_id', 'outcome', 'reason_code'}
    _require_parameters(parameters, required=required, allowed=allowed)
    result = assess_objective(
        objective_id=entity_id,
        campaign_id=str(parameters['campaign_id']),
        project_id=project_id,
        user_id=actor_id,
        expected_objective_version=expected_version,
        attack_path_id=str(parameters['attack_path_id']),
        evidence_id=str(parameters['evidence_id']),
        outcome=str(parameters['outcome']),
        reason_code=str(parameters['reason_code']),
        explanation=str(parameters.get('explanation') or ''),
        blast_radius_snapshot_id=(
            str(parameters['blast_radius_snapshot_id'])
            if parameters.get('blast_radius_snapshot_id')
            else None
        ),
        validation_id=str(parameters['validation_id']) if parameters.get('validation_id') else None,
    )
    return {
        'id': str(result.assessment.id),
        'assessment_id': str(result.assessment.id),
        'outcome': result.assessment.outcome,
        'proof_sha256': result.assessment.proof_sha256,
        'objective_version': result.objective.version,
        'objective_generation': result.objective.generation,
        'domain_replayed': result.replayed,
    }


def _execute_campaign_completion(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(parameters, required=set(), allowed=set())
    campaign = complete_campaign(
        campaign_id=entity_id,
        project_id=project_id,
        user_id=actor_id,
        expected_campaign_version=expected_version,
    )
    return {
        'id': str(campaign.id),
        'status': campaign.status,
        'version': campaign.version,
        'completion_sha256': campaign.completion_sha256,
        'domain_replayed': False,
    }


def _execute_finding_confirmation(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(
        parameters,
        required={'validation_id'},
        allowed={'validation_id', 'rationale'},
    )
    result = confirm_finding(
        finding_id=entity_id,
        validation_id=str(parameters['validation_id']),
        verdict='confirmed',
        rationale=str(parameters.get('rationale') or ''),
        actor_id=actor_id,
        expected_version=expected_version,
        emit_audit=False,
    )
    finding = Vulnerability.objects.only('id', 'status', 'validation_status', 'version').get(pk=entity_id)
    return {
        'id': str(result.confirmation.id),
        'confirmation_id': str(result.confirmation.id),
        'validation_id': str(result.confirmation.validation_run_id),
        'evidence_id': str(result.confirmation.evidence_id),
        'status': finding.status,
        'validation_status': finding.validation_status,
        'version': finding.version,
        'domain_replayed': result.replayed,
    }


def _execute_asset_authorization(
    *,
    authorized: bool,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    required = {'reason', '_agom_request_id', '_agom_correlation_id'}
    allowed = set(required)
    if authorized:
        allowed.add('expires_at')
    _require_parameters(parameters, required=required, allowed=allowed)
    result = govern_asset_authorization(
        asset_id=entity_id,
        project_id=project_id,
        actor_id=actor_id,
        expected_version=expected_version,
        authorized=authorized,
        reason=str(parameters['reason']),
        governed_request_id=str(parameters['_agom_request_id']),
        correlation_id=str(parameters['_agom_correlation_id']),
        expires_at=parameters.get('expires_at'),
    )
    return {
        'id': str(result.decision.id),
        'authorization_decision_id': str(result.decision.id),
        'authorized': bool(result.decision.authorized),
        'target_snapshot': result.decision.target_snapshot,
        'expires_at': result.decision.expires_at.isoformat() if result.decision.expires_at else None,
        'supersedes_id': str(result.decision.supersedes_id) if result.decision.supersedes_id else None,
        'version': result.version,
        'domain_replayed': result.replayed,
    }


def _execute_asset_authorization_approve(**kwargs) -> dict[str, Any]:
    return _execute_asset_authorization(authorized=True, **kwargs)


def _execute_asset_authorization_revoke(**kwargs) -> dict[str, Any]:
    return _execute_asset_authorization(authorized=False, **kwargs)


def _execute_finding_false_positive(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(
        parameters,
        required={'validation_id'},
        allowed={'validation_id', 'rationale'},
    )
    result = confirm_finding(
        finding_id=entity_id,
        validation_id=str(parameters['validation_id']),
        verdict='false_positive',
        rationale=str(parameters.get('rationale') or ''),
        actor_id=actor_id,
        expected_version=expected_version,
        emit_audit=False,
    )
    finding = Vulnerability.objects.only('id', 'status', 'validation_status', 'version').get(pk=entity_id)
    return {
        'id': str(result.confirmation.id),
        'confirmation_id': str(result.confirmation.id),
        'validation_id': str(result.confirmation.validation_run_id),
        'evidence_id': str(result.confirmation.evidence_id),
        'status': finding.status,
        'validation_status': finding.validation_status,
        'version': finding.version,
        'domain_replayed': result.replayed,
    }


def _parse_review_at(value: Any) -> datetime | None:
    if value in (None, ''):
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError as exc:
        raise GovernedActionError('review_at must be a valid ISO-8601 timestamp.') from exc


def _execute_finding_disposition(
    *,
    disposition: str,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    if disposition in {
        FindingDisposition.Disposition.ACCEPTED_RISK,
        FindingDisposition.Disposition.WONT_FIX,
    }:
        _require_parameters(
            parameters,
            required={'rationale', 'risk_correlation_id', 'review_at'},
            allowed={'rationale', 'risk_correlation_id', 'review_at'},
        )
    else:
        _require_parameters(
            parameters,
            required={'rationale', 'duplicate_of_id'},
            allowed={'rationale', 'duplicate_of_id'},
        )

    result = govern_finding_disposition(
        finding_id=entity_id,
        disposition=disposition,
        rationale=str(parameters.get('rationale') or ''),
        actor_id=actor_id,
        risk_correlation_id=parameters.get('risk_correlation_id'),
        review_at=_parse_review_at(parameters.get('review_at')),
        duplicate_of_id=parameters.get('duplicate_of_id'),
        expected_version=expected_version,
        emit_audit=False,
    )
    finding = Vulnerability.objects.only('id', 'status', 'version', 'duplicate_of_id').get(pk=entity_id)
    return {
        'id': str(result.disposition.id),
        'disposition_id': str(result.disposition.id),
        'disposition': result.disposition.disposition,
        'status': finding.status,
        'version': finding.version,
        'risk_correlation_id': (
            str(result.disposition.risk_correlation_id)
            if result.disposition.risk_correlation_id else None
        ),
        'duplicate_of_id': str(finding.duplicate_of_id) if finding.duplicate_of_id else None,
        'review_at': (
            result.disposition.review_at.isoformat()
            if result.disposition.review_at else None
        ),
        'domain_replayed': result.replayed,
    }


def _execute_accept_risk(**kwargs) -> dict[str, Any]:
    return _execute_finding_disposition(
        disposition=FindingDisposition.Disposition.ACCEPTED_RISK,
        **kwargs,
    )


def _execute_wont_fix(**kwargs) -> dict[str, Any]:
    return _execute_finding_disposition(
        disposition=FindingDisposition.Disposition.WONT_FIX,
        **kwargs,
    )


def _execute_duplicate(**kwargs) -> dict[str, Any]:
    return _execute_finding_disposition(
        disposition=FindingDisposition.Disposition.DUPLICATE,
        **kwargs,
    )


def _execute_investigation_closure(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(
        parameters,
        required={'finding_id', 'closure_type', 'rationale'},
        allowed={'finding_id', 'closure_type', 'rationale', 'validation_id', 'disposition_id'},
    )
    result = close_investigation_case(
        case_id=entity_id,
        project_id=project_id,
        user_id=actor_id,
        expected_version=expected_version,
        finding_id=str(parameters['finding_id']),
        closure_type=str(parameters['closure_type']),
        rationale=str(parameters.get('rationale') or ''),
        validation_id=str(parameters['validation_id']) if parameters.get('validation_id') else None,
        disposition_id=str(parameters['disposition_id']) if parameters.get('disposition_id') else None,
    )
    return {
        'id': str(result.closure.id),
        'closure_id': str(result.closure.id),
        'closure_type': result.closure.closure_type,
        'finding_id': str(result.closure.finding_id),
        'validation_id': str(result.closure.validation_run_id) if result.closure.validation_run_id else None,
        'disposition_id': str(result.closure.disposition_id) if result.closure.disposition_id else None,
        'evidence_id': str(result.closure.evidence_id) if result.closure.evidence_id else None,
        'source_sha256': result.closure.source_sha256,
        'closure_fingerprint': result.closure.closure_fingerprint,
        'version': result.state.version,
        'domain_replayed': result.replayed,
    }


def _execute_detection_publication(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(
        parameters,
        required={'integration_id', '_agom_request_id', '_agom_correlation_id'},
        allowed={'integration_id', '_agom_request_id', '_agom_correlation_id'},
    )
    try:
        result = queue_publication_delivery(
            revision_id=entity_id,
            integration_id=str(parameters['integration_id']),
            project_id=project_id,
            user_id=actor_id,
            expected_version=expected_version,
            governed_request_id=str(parameters['_agom_request_id']),
            correlation_id=str(parameters['_agom_correlation_id']),
        )
    except PermissionError:
        raise
    except DetectionEngineeringError as exc:
        raise GovernedActionError(str(exc)) from exc
    delivery = result.delivery
    return {
        'id': str(delivery.id),
        'delivery_id': str(delivery.id),
        'delivery_status': delivery.status,
        'integration_id': str(delivery.integration_id),
        'live_acceptance_id': str(delivery.live_acceptance_id),
        'package_sha256': delivery.package_sha256,
        'configuration_fingerprint': delivery.integration_configuration_fingerprint,
        'version': expected_version + (0 if result.replayed else 1),
        'domain_replayed': result.replayed,
    }


def _execute_integration_live_acceptance(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(
        parameters,
        required={'acceptance_test_id', 'vendor_ack', 'acceptance_evidence_sha256', 'review_at'},
        allowed={'acceptance_test_id', 'vendor_ack', 'acceptance_evidence_sha256', 'review_at', 'expires_at'},
    )
    try:
        result = accept_integration_live(
            integration_id=entity_id,
            project_id=project_id,
            actor_id=actor_id,
            expected_version=expected_version,
            acceptance_test_id=str(parameters['acceptance_test_id']),
            vendor_ack=str(parameters['vendor_ack']),
            acceptance_evidence_sha256=str(parameters['acceptance_evidence_sha256']),
            review_at=parameters['review_at'],
            expires_at=parameters.get('expires_at'),
        )
    except IntegrationAcceptanceConflict as exc:
        raise GovernedActionConflict(str(exc)) from exc
    except IntegrationAcceptanceError as exc:
        raise GovernedActionError(str(exc)) from exc
    acceptance = result.acceptance
    return {
        'id': str(acceptance.id),
        'acceptance_id': str(acceptance.id),
        'acceptance_test_id': str(acceptance.acceptance_test_id),
        'acceptance_test_fingerprint': acceptance.acceptance_test.test_fingerprint,
        'vendor_ack': acceptance.vendor_ack,
        'acceptance_evidence_sha256': acceptance.acceptance_evidence_sha256,
        'review_at': acceptance.review_at.isoformat(),
        'expires_at': acceptance.expires_at.isoformat() if acceptance.expires_at else None,
        'supersedes_id': str(acceptance.supersedes_id) if acceptance.supersedes_id else None,
        'acceptance_fingerprint': acceptance.acceptance_fingerprint,
        'version': result.generation,
        'domain_replayed': False,
    }


def _execute_finding_closure(
    *,
    project_id: str,
    actor_id: str,
    entity_id: str,
    expected_version: int,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _require_parameters(parameters, required=set(), allowed=set())
    result = close_finding(
        finding_id=entity_id,
        actor_id=actor_id,
        expected_version=expected_version,
        emit_audit=False,
    )
    return {
        'id': str(result.finding.id),
        'status': result.finding.status,
        'validation_status': result.finding.validation_status,
        'version': result.finding.version,
        'validation_id': str(result.validation.id),
        'evidence_id': str(result.evidence.id),
        'domain_replayed': False,
    }


_DISPATCH: dict[str, Callable[..., dict[str, Any]]] = {
    'asset.authorization.approve': _execute_asset_authorization_approve,
    'asset.authorization.revoke': _execute_asset_authorization_revoke,
    'campaign.objective.assess': _execute_objective_assessment,
    'campaign.complete': _execute_campaign_completion,
    'detection.publish': _execute_detection_publication,
    'finding.confirm': _execute_finding_confirmation,
    'finding.false_positive': _execute_finding_false_positive,
    'finding.disposition.accept_risk': _execute_accept_risk,
    'finding.disposition.wont_fix': _execute_wont_fix,
    'finding.disposition.duplicate': _execute_duplicate,
    'finding.close': _execute_finding_closure,
    'investigation.close': _execute_investigation_closure,
    'integration.live_accept': _execute_integration_live_acceptance,
}


def execute_governed_action(
    *,
    action_id: str,
    project_id: str,
    actor_id: str,
    entity_type: str,
    entity_id: str,
    expected_version: int,
    idempotency_key: str,
    parameters: dict[str, Any] | None = None,
    request_id: str | None = None,
    correlation_id: uuid.UUID | str | None = None,
    ip_address: str = '127.0.0.1',
    user_agent: str = '',
    session_id: str = '',
) -> GovernedActionResult:
    normalized_action = str(action_id or '').strip()
    normalized_entity_type = str(entity_type or '').strip().lower()
    normalized_entity_id = str(entity_id or '').strip()
    normalized_project_id = str(project_id or '').strip()
    normalized_actor_id = str(actor_id or '').strip()
    key = _normalize_idempotency_key(idempotency_key)
    payload = dict(parameters or {})
    if any(str(key).startswith('_agom_') for key in payload):
        raise GovernedActionError('Governed action parameters may not use the reserved _agom_ namespace.')
    requested_correlation = str(correlation_id or '').strip()
    normalized_request_id = str(request_id or '').strip()

    if not normalized_actor_id:
        raise GovernedActionError('Authenticated actor id is required.')
    if not normalized_project_id or not normalized_entity_type or not normalized_entity_id:
        raise GovernedActionError('project_id, entity_type and entity_id are required.')
    if int(expected_version) < 1:
        raise GovernedActionError('expected_version must be at least 1.')
    if normalized_action in _REQUEST_REQUIRED_ACTIONS and not normalized_request_id:
        raise GovernedActionError('This governed action requires an immutable request_id.')

    contract = get_action_contract(normalized_action)
    if contract is None:
        raise GovernedActionError('Unknown governed action contract.')
    if contract.entity_type != normalized_entity_type:
        raise GovernedActionError('Governed action entity_type does not match its canonical ActionContract.')
    if normalized_action not in _IMPLEMENTED_ACTIONS or normalized_action not in _DISPATCH:
        raise GovernedActionError('Governed action execution is not implemented for this ActionContract and remains fail-closed.')

    request_material = {
        'contract_version': AGOM_CONTRACT_VERSION,
        'action_id': normalized_action,
        'project_id': normalized_project_id,
        'actor_id': normalized_actor_id,
        'entity_type': normalized_entity_type,
        'entity_id': normalized_entity_id,
        'expected_version': int(expected_version),
        'idempotency_key': key,
        'requested_correlation_id': requested_correlation,
        'governed_request_id': normalized_request_id,
        'parameters': payload,
    }
    request_fingerprint = _sha(request_material)

    # Preserve exact idempotent replay semantics before fresh-state preflight.
    outer_organization_id, _outer_project = _project_scope(normalized_project_id)
    prior_execution = (
        GovernedActionExecution.objects.select_related('audit_log')
        .filter(organization_id=outer_organization_id, idempotency_key=key)
        .first()
    )
    if prior_execution is not None:
        if prior_execution.request_fingerprint != request_fingerprint:
            raise GovernedActionConflict(
                'Idempotency key was already used for a different governed action request in this organization.'
            )
        return GovernedActionResult(execution=prior_execution, replayed=True)

    preflight_request = None
    if normalized_request_id:
        preflight_request = _bound_governed_request(
            request_id=normalized_request_id,
            organization_id=outer_organization_id,
            project_id=normalized_project_id,
            action_id=normalized_action,
            entity_type=normalized_entity_type,
            entity_id=normalized_entity_id,
            expected_version=int(expected_version),
            parameters=payload,
            actor_id=normalized_actor_id,
            lock=False,
        )
        if requested_correlation and str(preflight_request.correlation_id) != requested_correlation:
            raise GovernedActionConflict('Execution correlation_id does not match the immutable governed request.')

        # A governed request is version-bound. Check the current projection
        # before dynamic evidence/temporal gates so a newer immutable domain
        # generation is reported deterministically as a CAS conflict rather
        # than being misclassified as missing/stale evidence.
        preflight_manifest = build_governed_capability_manifest(
            project_id=normalized_project_id,
            user_id=normalized_actor_id,
            entity_type=normalized_entity_type,
            entity_id=normalized_entity_id,
            request_proposer_id=str(preflight_request.requested_by_id),
            execution_parameters=payload,
        )
        preflight_capability = _capability_for(preflight_manifest, normalized_action)
        if preflight_capability.mode is ActionMode.HIDDEN:
            raise PermissionError('Governed action is not available to this actor.')
        preflight_version = preflight_manifest.projection.version
        if preflight_version is None:
            raise GovernedActionError('Governed action target does not expose a version for CAS enforcement.')
        if int(preflight_version) != int(expected_version):
            raise GovernedActionConflict(
                f'Expected entity version {expected_version}, current version is {preflight_version}.'
            )

    # Persist qualification before mutation so rejected evidence decisions remain
    # auditable. Capability authority is checked first to avoid evidence-state
    # disclosure to an ineligible actor.
    prequalification = _preflight_evidence_qualification(
        action_id=normalized_action,
        project_id=normalized_project_id,
        actor_id=normalized_actor_id,
        entity_type=normalized_entity_type,
        entity_id=normalized_entity_id,
        parameters=payload,
        request_proposer_id=(
            str(preflight_request.requested_by_id)
            if preflight_request is not None else ''
        ),
    )
    pretemporal = _preflight_temporal_policy(
        action_id=normalized_action,
        project_id=normalized_project_id,
        actor_id=normalized_actor_id,
        entity_type=normalized_entity_type,
        entity_id=normalized_entity_id,
        parameters=payload,
        request_proposer_id=(
            str(preflight_request.requested_by_id)
            if preflight_request is not None else ''
        ),
    )

    with transaction.atomic():
        # Resolve the immutable tenant link only to discover the serialization
        # root, then lock Organization first. Responsibility grant/revoke uses
        # the same lock order, preventing authority TOCTOU during execution.
        organization_id, project = _project_scope(normalized_project_id)
        organization = (
            Organization.objects.select_for_update(of=('self',))
            .filter(pk=organization_id, is_active=True)
            .first()
        )
        if organization is None:
            raise GovernedActionError('Governed action organization is not active.')
        link = (
            TenantProject.objects.select_for_update(of=('self',))
            .filter(project_id=normalized_project_id, organization=organization)
            .first()
        )
        if link is None:
            raise GovernedActionError('Governed action project scope changed during execution.')

        replay = (
            GovernedActionExecution.objects.select_for_update(of=('self',))
            .select_related('audit_log')
            .filter(organization=organization, idempotency_key=key)
            .first()
        )
        if replay is not None:
            if replay.request_fingerprint != request_fingerprint:
                raise GovernedActionConflict(
                    'Idempotency key was already used for a different governed action request in this organization.'
                )
            return GovernedActionResult(execution=replay, replayed=True)

        governed_request = None
        if normalized_request_id:
            governed_request = _bound_governed_request(
                request_id=normalized_request_id,
                organization_id=str(organization.id),
                project_id=normalized_project_id,
                action_id=normalized_action,
                entity_type=normalized_entity_type,
                entity_id=normalized_entity_id,
                expected_version=int(expected_version),
                parameters=payload,
                actor_id=normalized_actor_id,
                lock=True,
            )
            if requested_correlation and str(governed_request.correlation_id) != requested_correlation:
                raise GovernedActionConflict('Execution correlation_id does not match the immutable governed request.')

        manifest = build_governed_capability_manifest(
            project_id=normalized_project_id,
            user_id=normalized_actor_id,
            entity_type=normalized_entity_type,
            entity_id=normalized_entity_id,
            request_proposer_id=(
                str(governed_request.requested_by_id)
                if governed_request is not None else ''
            ),
            execution_parameters=payload if governed_request is not None else None,
        )
        if str(manifest.entity.tenant_id or '') != str(organization.id):
            raise GovernedActionError('Capability tenant lineage does not match the locked organization.')
        if str(manifest.entity.project_id or '') != normalized_project_id:
            raise GovernedActionError('Capability project lineage does not match the governed request.')

        capability = _capability_for(manifest, normalized_action)
        if capability.mode is ActionMode.HIDDEN:
            raise PermissionError('Governed action is not available to this actor.')

        # Re-check CAS after acquiring the serialization locks and before
        # mutable/dynamic gates. This closes the race between preflight and
        # execution and preserves a single stale-version conflict semantic.
        current_version = manifest.projection.version
        if current_version is None:
            raise GovernedActionError('Governed action target does not expose a version for CAS enforcement.')
        if int(current_version) != int(expected_version):
            raise GovernedActionConflict(
                f'Expected entity version {expected_version}, current version is {current_version}.'
            )

        if capability.mode is not ActionMode.ENABLED:
            raise GovernedActionBlocked(
                capability.reason_code,
                capability.reason,
                capability.missing_requirements,
            )

        gate_snapshot = [item.model_dump(mode='json') for item in capability.gate_results]
        gate_policy_versions = sorted({str(item.policy_version or '') for item in capability.gate_results})
        policy_material = {
            'contract_version': AGOM_CONTRACT_VERSION,
            'action_contract': contract.model_dump(mode='json'),
            'evaluation_policy_version': manifest.evaluation_policy_version,
            'gate_policy_versions': gate_policy_versions,
        }
        policy_fingerprint = _sha(policy_material)
        before_projection = _projection_dict(manifest)

        qualification = None
        if normalized_action in {'finding.confirm', 'finding.false_positive'}:
            qualification = _finding_confirmation_qualification(
                project_id=normalized_project_id,
                actor_id=normalized_actor_id,
                entity_id=normalized_entity_id,
                parameters=payload,
                evaluated_at=prequalification.evaluation.evaluated_at if prequalification else None,
            )
            _require_qualified_evidence(qualification)
        elif normalized_action == 'investigation.close':
            qualification = _investigation_closure_qualification(
                project_id=normalized_project_id,
                actor_id=normalized_actor_id,
                case_id=normalized_entity_id,
                parameters=payload,
                evaluated_at=prequalification.evaluation.evaluated_at if prequalification else None,
            )
            if str(payload.get('closure_type') or '').strip() == 'remediated':
                _require_qualified_evidence(qualification)

        temporal = _preflight_temporal_policy(
            action_id=normalized_action,
            project_id=normalized_project_id,
            actor_id=normalized_actor_id,
            entity_type=normalized_entity_type,
            entity_id=normalized_entity_id,
            parameters=payload,
            evaluated_at=pretemporal.evaluation.evaluated_at,
            request_proposer_id=(
                str(governed_request.requested_by_id)
                if governed_request is not None else ''
            ),
        )

        correlation_uuid = (
            uuid.UUID(requested_correlation)
            if requested_correlation
            else governed_request.correlation_id if governed_request is not None else uuid.uuid4()
        )
        dispatcher = _DISPATCH[normalized_action]
        dispatch_parameters = payload
        if normalized_action in {
            'asset.authorization.approve',
            'asset.authorization.revoke',
            'detection.publish',
        }:
            if governed_request is None:
                raise GovernedActionError('This governed action requires an immutable governed request.')
            dispatch_parameters = {
                **payload,
                '_agom_request_id': str(governed_request.id),
                '_agom_correlation_id': str(correlation_uuid),
            }
        result_payload = dispatcher(
            project_id=normalized_project_id,
            actor_id=normalized_actor_id,
            entity_id=normalized_entity_id,
            expected_version=int(expected_version),
            parameters=dispatch_parameters,
        )
        if qualification is not None:
            result_payload = {
                **result_payload,
                'evidence_qualification': _qualification_view(qualification),
            }
        result_payload = {
            **result_payload,
            'temporal_policy': _temporal_view(temporal),
        }

        after_manifest = build_governed_capability_manifest(
            project_id=normalized_project_id,
            user_id=normalized_actor_id,
            entity_type=normalized_entity_type,
            entity_id=normalized_entity_id,
        )
        after_projection = _projection_dict(after_manifest)
        audit = append_audit(
            user_id=normalized_actor_id,
            action=AuditLog.Action.API_REQUEST,
            result=AuditLog.Result.SUCCESS,
            resource_type=normalized_entity_type,
            resource_id=normalized_entity_id,
            resource_repr=normalized_action,
            changes={
                'before_projection': before_projection,
                'after_projection': after_projection,
            },
            metadata={
                'agom_contract_version': AGOM_CONTRACT_VERSION,
                'governed_action_id': normalized_action,
                'contract_policy_version': contract.policy_version,
                'evaluation_policy_version': manifest.evaluation_policy_version,
                'policy_fingerprint': policy_fingerprint,
                'idempotency_key': key,
                'request_fingerprint': request_fingerprint,
                'governed_request_id': str(governed_request.id) if governed_request else None,
                'governed_request_fingerprint': governed_request.request_fingerprint if governed_request else None,
                'governed_request_proposer_id': str(governed_request.requested_by_id) if governed_request else None,
                'correlation_id': str(correlation_uuid),
                'gate_snapshot': gate_snapshot,
                'result_payload': result_payload,
            },
            ip_address=ip_address,
            user_agent=str(user_agent or ''),
            session_id=str(session_id or ''),
            request_id=correlation_uuid,
        )

        execution_material = {
            'request_fingerprint': request_fingerprint,
            'governed_request_id': str(governed_request.id) if governed_request else None,
            'governed_request_fingerprint': governed_request.request_fingerprint if governed_request else None,
            'policy_fingerprint': policy_fingerprint,
            'before_projection': before_projection,
            'gate_snapshot': gate_snapshot,
            'result_payload': result_payload,
            'after_projection': after_projection,
            'audit_id': str(audit.id),
            'audit_chain_index': audit.chain_index,
            'audit_entry_hash': audit.entry_hash,
            'correlation_id': str(correlation_uuid),
        }
        execution_fingerprint = _sha(execution_material)
        execution = GovernedActionExecution.objects.create(
            organization=organization,
            project=project,
            actor_id=normalized_actor_id,
            request=governed_request,
            action_id=normalized_action,
            entity_type=normalized_entity_type,
            entity_id=normalized_entity_id,
            expected_version=int(expected_version),
            idempotency_key=key,
            request_fingerprint=request_fingerprint,
            contract_version=AGOM_CONTRACT_VERSION,
            contract_policy_version=contract.policy_version,
            evaluation_policy_version=manifest.evaluation_policy_version,
            policy_fingerprint=policy_fingerprint,
            correlation_id=correlation_uuid,
            request_payload=request_material,
            before_projection=before_projection,
            gate_snapshot=gate_snapshot,
            result_payload=result_payload,
            after_projection=after_projection,
            audit_log=audit,
            execution_fingerprint=execution_fingerprint,
        )
        return GovernedActionResult(execution=execution, replayed=False)


def governed_action_view(result: GovernedActionResult) -> dict[str, Any]:
    item = result.execution
    audit = item.audit_log
    return {
        'execution_id': str(item.id),
        'action_id': item.action_id,
        'organization_id': str(item.organization_id),
        'project_id': str(item.project_id),
        'actor_id': str(item.actor_id),
        'request_id': str(item.request_id) if item.request_id else None,
        'entity_type': item.entity_type,
        'entity_id': item.entity_id,
        'expected_version': item.expected_version,
        'idempotency_key': item.idempotency_key,
        'request_fingerprint': item.request_fingerprint,
        'contract_version': item.contract_version,
        'contract_policy_version': item.contract_policy_version,
        'evaluation_policy_version': item.evaluation_policy_version,
        'policy_fingerprint': item.policy_fingerprint,
        'correlation_id': item.correlation_id,
        'before_projection': item.before_projection,
        'gate_results': item.gate_snapshot,
        'result': item.result_payload,
        'after_projection': item.after_projection,
        'audit': {
            'audit_id': str(audit.id),
            'chain_index': audit.chain_index,
            'entry_hash': audit.entry_hash,
        },
        'execution_fingerprint': item.execution_fingerprint,
        'replayed': result.replayed,
        'created_at': item.created_at,
    }
