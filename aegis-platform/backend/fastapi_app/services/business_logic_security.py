from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.db.models import Q

from django_project.projects.models import Project
from enterprise.governed_action_models import BusinessLogicAssessment, GovernedActionRequest
from enterprise.models import OrganizationMembership
from fastapi_app.contracts.governed_operations import AGOM_CONTRACT_VERSION, ActionMode
from fastapi_app.services.entity_capability_adapters import build_entity_capability_manifest
from fastapi_app.services.governed_operations import get_action_contract


BUSINESS_LOGIC_CONTRACT_VERSION = 'aegis.business-logic.v1'


class BusinessLogicAssessmentError(ValueError):
    pass


@dataclass(frozen=True)
class BusinessLogicAssessmentResult:
    assessment: BusinessLogicAssessment
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


def _stable_manifest(manifest) -> dict[str, Any]:
    data = manifest.model_dump(mode='json')
    data.pop('generated_at', None)
    for capability in data.get('capabilities', []):
        for gate in capability.get('gate_results', []):
            gate.pop('evaluated_at', None)
    return data


def _request_fingerprint(row: GovernedActionRequest) -> str:
    return _sha({
        'contract_version': row.contract_version,
        'contract_fingerprint': row.contract_fingerprint,
        'project_id': str(row.project_id),
        'requested_by_id': str(row.requested_by_id),
        'action_id': row.action_id,
        'entity_type': row.entity_type,
        'entity_id': row.entity_id,
        'expected_version': int(row.expected_version),
        'parameters': dict(row.parameters_snapshot or {}),
    })


def _contract_fingerprint(snapshot: dict[str, Any]) -> str:
    return _sha({
        'contract_version': AGOM_CONTRACT_VERSION,
        'contract': snapshot,
    })


def _invariant(
    invariant_id: str,
    passed: bool,
    reason_code: str,
    detail: str,
    **evidence: Any,
) -> dict[str, Any]:
    return {
        'invariant_id': invariant_id,
        'status': 'pass' if passed else 'blocked',
        'reason_code': reason_code,
        'detail': detail,
        'evidence': evidence,
    }


def _request_for_actor(*, request_id: str, actor_id: str) -> GovernedActionRequest:
    row = (
        GovernedActionRequest.objects
        .select_related('organization', 'project', 'requested_by')
        .filter(pk=request_id)
        .first()
    )
    if row is None:
        raise BusinessLogicAssessmentError('Governed action request was not found.')
    membership = OrganizationMembership.objects.filter(
        organization=row.organization,
        user_id=actor_id,
        user__is_active=True,
        is_active=True,
    ).exists()
    project_access = Project.objects.filter(pk=row.project_id).filter(
        Q(owner_id=actor_id) | Q(members__id=actor_id)
    ).exists()
    if not membership or not project_access:
        raise PermissionError('Active tenant and project membership are required for business-logic assessment.')
    return row


@transaction.atomic
def assess_governed_action_request(
    *,
    request_id: str,
    assessed_by_id: str,
) -> BusinessLogicAssessmentResult:
    row = _request_for_actor(request_id=str(request_id), actor_id=str(assessed_by_id))
    row = (
        GovernedActionRequest.objects.select_for_update()
        .select_related('organization', 'project', 'requested_by')
        .get(pk=row.pk)
    )

    contract = get_action_contract(row.action_id)
    if contract is None:
        current_contract_snapshot: dict[str, Any] = {}
        current_contract_fingerprint = ''
    else:
        current_contract_snapshot = contract.model_dump(mode='json')
        current_contract_fingerprint = _contract_fingerprint(current_contract_snapshot)

    manifest = build_entity_capability_manifest(
        project_id=str(row.project_id),
        user_id=str(assessed_by_id),
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        request_proposer_id=str(row.requested_by_id),
        execution_parameters=dict(row.parameters_snapshot or {}),
    )
    stable_manifest = _stable_manifest(manifest)
    capabilities = {
        str(item.get('action_id')): item
        for item in stable_manifest.get('capabilities', [])
        if isinstance(item, dict)
    }
    capability = capabilities.get(row.action_id)
    projection = dict(stable_manifest.get('projection') or {})

    stored_contract_snapshot = dict(row.contract_snapshot or {})
    stored_contract_fingerprint = _contract_fingerprint(stored_contract_snapshot)
    recomputed_request_fingerprint = _request_fingerprint(row)

    invariants: list[dict[str, Any]] = []

    request_integrity_ok = recomputed_request_fingerprint == row.request_fingerprint
    invariants.append(_invariant(
        'request_integrity',
        request_integrity_ok,
        'REQUEST_INTEGRITY_OK' if request_integrity_ok else 'REQUEST_FINGERPRINT_MISMATCH',
        'Immutable request fingerprint matches its stored semantic payload.' if request_integrity_ok
        else 'Stored governed request fields no longer match the immutable request fingerprint.',
        expected_sha256=recomputed_request_fingerprint,
        stored_sha256=row.request_fingerprint,
    ))

    stored_contract_ok = stored_contract_fingerprint == row.contract_fingerprint
    invariants.append(_invariant(
        'stored_contract_integrity',
        stored_contract_ok,
        'STORED_CONTRACT_INTEGRITY_OK' if stored_contract_ok else 'CONTRACT_SNAPSHOT_MISMATCH',
        'Stored contract snapshot matches its immutable fingerprint.' if stored_contract_ok
        else 'Stored contract snapshot failed fingerprint verification.',
        expected_sha256=stored_contract_fingerprint,
        stored_sha256=row.contract_fingerprint,
    ))

    contract_current_ok = bool(
        contract is not None
        and row.contract_version == AGOM_CONTRACT_VERSION
        and contract.entity_type == row.entity_type
        and contract.policy_version == row.contract_policy_version
        and current_contract_fingerprint == row.contract_fingerprint
    )
    invariants.append(_invariant(
        'contract_continuity',
        contract_current_ok,
        'CURRENT_CONTRACT_MATCH' if contract_current_ok else 'CONTRACT_DRIFT',
        'Current canonical action contract is identical to the request-bound contract.' if contract_current_ok
        else 'The current action contract differs from the immutable request contract.',
        current_contract_fingerprint=current_contract_fingerprint,
        stored_contract_fingerprint=row.contract_fingerprint,
        current_policy_version=(contract.policy_version if contract else ''),
        stored_policy_version=row.contract_policy_version,
    ))

    entity_binding_ok = bool(
        str(stable_manifest.get('entity', {}).get('entity_type') or '') == row.entity_type
        and str(stable_manifest.get('entity', {}).get('entity_id') or '') == row.entity_id
        and str(stable_manifest.get('entity', {}).get('project_id') or '') == str(row.project_id)
        and str(stable_manifest.get('entity', {}).get('tenant_id') or '') == str(row.organization_id)
    )
    invariants.append(_invariant(
        'entity_tenant_binding',
        entity_binding_ok,
        'ENTITY_BINDING_OK' if entity_binding_ok else 'ENTITY_BINDING_MISMATCH',
        'Current authoritative entity projection remains bound to the request tenant and project.' if entity_binding_ok
        else 'Current entity projection no longer matches the immutable request scope.',
        entity=stable_manifest.get('entity', {}),
    ))

    current_version = projection.get('version')
    version_ok = bool(
        contract is not None
        and (
            not contract.expected_version_required
            or current_version is not None and int(current_version) == int(row.expected_version)
        )
    )
    invariants.append(_invariant(
        'optimistic_version_precondition',
        version_ok,
        'EXPECTED_VERSION_CURRENT' if version_ok else 'EXPECTED_VERSION_STALE',
        'Entity version still satisfies the immutable request precondition.' if version_ok
        else 'Entity version changed after the request was created.',
        expected_version=int(row.expected_version),
        current_version=current_version,
    ))

    capability_enabled = bool(
        capability is not None
        and capability.get('mode') == ActionMode.ENABLED.value
    )
    capability_reason = str((capability or {}).get('reason_code') or '')
    invariants.append(_invariant(
        'current_capability',
        capability_enabled,
        'CURRENT_CAPABILITY_ENABLED' if capability_enabled else 'CURRENT_CAPABILITY_BLOCKED',
        'Current responsibilities, SoD, evidence and governance gates permit this request.' if capability_enabled
        else 'Current authoritative capability evaluation blocks this request.',
        capability_mode=(capability or {}).get('mode'),
        capability_reason_code=capability_reason,
        missing_requirements=list((capability or {}).get('missing_requirements') or []),
    ))

    already_executed = hasattr(row, 'execution')
    invariants.append(_invariant(
        'single_execution_boundary',
        not already_executed,
        'REQUEST_NOT_EXECUTED' if not already_executed else 'REQUEST_ALREADY_EXECUTED',
        'Request has not consumed its single governed execution boundary.' if not already_executed
        else 'Request already has an immutable governed execution and cannot be reused.',
        execution_id=(str(row.execution.id) if already_executed else ''),
    ))

    failed = [item for item in invariants if item['status'] != 'pass']
    decision = (
        BusinessLogicAssessment.Decision.PASSED
        if not failed
        else BusinessLogicAssessment.Decision.BLOCKED
    )
    reason_codes = sorted({str(item['reason_code']) for item in failed})
    material = {
        'contract_version': BUSINESS_LOGIC_CONTRACT_VERSION,
        'request_id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'assessed_by_id': str(assessed_by_id),
        'action_id': row.action_id,
        'entity_type': row.entity_type,
        'entity_id': row.entity_id,
        'request_fingerprint': row.request_fingerprint,
        'stored_contract_fingerprint': row.contract_fingerprint,
        'current_contract_fingerprint': current_contract_fingerprint,
        'evaluation_policy_version': str(stable_manifest.get('evaluation_policy_version') or ''),
        'projection': projection,
        'capability': capability or {},
        'invariants': invariants,
        'decision': decision,
        'reason_codes': reason_codes,
    }
    assessment_sha256 = _sha(material)

    existing = BusinessLogicAssessment.objects.filter(
        assessment_sha256=assessment_sha256
    ).first()
    if existing is not None:
        if existing.organization_id != row.organization_id or existing.project_id != row.project_id:
            raise BusinessLogicAssessmentError('Business-logic assessment digest crossed a tenant boundary.')
        return BusinessLogicAssessmentResult(existing, True)

    assessment = BusinessLogicAssessment.objects.create(
        organization=row.organization,
        project=row.project,
        request=row,
        assessed_by_id=assessed_by_id,
        action_id=row.action_id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        request_fingerprint=row.request_fingerprint,
        contract_fingerprint=row.contract_fingerprint,
        evaluation_policy_version=str(stable_manifest.get('evaluation_policy_version') or ''),
        projection_snapshot=projection,
        capability_snapshot=capability or {},
        invariant_results=invariants,
        decision=decision,
        reason_codes=reason_codes,
        assessment_sha256=assessment_sha256,
    )
    return BusinessLogicAssessmentResult(assessment, False)


def serialize_business_logic_assessment(result: BusinessLogicAssessmentResult | BusinessLogicAssessment) -> dict[str, Any]:
    row = result.assessment if isinstance(result, BusinessLogicAssessmentResult) else result
    replayed = result.replayed if isinstance(result, BusinessLogicAssessmentResult) else False
    return {
        'id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'request_id': str(row.request_id),
        'assessed_by_id': str(row.assessed_by_id),
        'action_id': row.action_id,
        'entity_type': row.entity_type,
        'entity_id': row.entity_id,
        'request_fingerprint': row.request_fingerprint,
        'contract_fingerprint': row.contract_fingerprint,
        'evaluation_policy_version': row.evaluation_policy_version,
        'projection_snapshot': row.projection_snapshot,
        'capability_snapshot': row.capability_snapshot,
        'invariant_results': row.invariant_results,
        'decision': row.decision,
        'reason_codes': row.reason_codes,
        'assessment_sha256': row.assessment_sha256,
        'replayed': replayed,
        'created_at': row.created_at.isoformat(),
    }
