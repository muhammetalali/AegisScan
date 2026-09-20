from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.db.models import Q

from django_project.projects.models import Project
from enterprise.governed_action_models import GovernedActionRequest
from enterprise.models import Organization, OrganizationMembership, TenantProject
from fastapi_app.contracts.governed_operations import AGOM_CONTRACT_VERSION
from fastapi_app.services.entity_capability_adapters import resolve_entity_capability_context
from fastapi_app.services.governed_operations import get_action_contract


class GovernedActionRequestError(ValueError):
    pass


class GovernedActionRequestConflict(GovernedActionRequestError):
    pass


@dataclass(frozen=True)
class GovernedActionRequestResult:
    request: GovernedActionRequest
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _normalize_key(value: str) -> str:
    key = str(value or '').strip()
    if not key:
        raise GovernedActionRequestError('A non-empty idempotency_key is required.')
    if len(key) > 128:
        raise GovernedActionRequestError('idempotency_key exceeds 128 characters.')
    return key


def create_governed_action_request(
    *,
    project_id: str,
    requested_by_id: str,
    action_id: str,
    entity_type: str,
    entity_id: str,
    expected_version: int,
    idempotency_key: str,
    parameters: dict[str, Any] | None = None,
    correlation_id: uuid.UUID | str | None = None,
) -> GovernedActionRequestResult:
    normalized_project = str(project_id or '').strip()
    normalized_actor = str(requested_by_id or '').strip()
    normalized_action = str(action_id or '').strip()
    normalized_type = str(entity_type or '').strip().lower()
    normalized_entity = str(entity_id or '').strip()
    key = _normalize_key(idempotency_key)
    payload = dict(parameters or {})
    if not normalized_project or not normalized_actor or not normalized_action or not normalized_type or not normalized_entity:
        raise GovernedActionRequestError('project_id, requested_by_id, action_id, entity_type, and entity_id are required.')
    if int(expected_version) < 1:
        raise GovernedActionRequestError('expected_version must be at least 1.')

    with transaction.atomic():
        identity = (
            TenantProject.objects.filter(project_id=normalized_project, organization__is_active=True)
            .values('id', 'organization_id')
            .first()
        )
        if identity is None:
            raise GovernedActionRequestError('Project is not bound to an active enterprise tenant.')
        organization = (
            Organization.objects.select_for_update(of=('self',))
            .filter(pk=identity['organization_id'], is_active=True)
            .first()
        )
        if organization is None:
            raise GovernedActionRequestError('Project enterprise tenant is not active.')
        link = (
            TenantProject.objects.select_for_update(of=('self',))
            .filter(pk=identity['id'], project_id=normalized_project, organization=organization)
            .first()
        )
        if link is None:
            raise GovernedActionRequestError('Project enterprise scope changed while creating the request.')
        membership = OrganizationMembership.objects.filter(
            organization=organization,
            user_id=normalized_actor,
            user__is_active=True,
            is_active=True,
        ).first()
        project_access = Project.objects.filter(pk=normalized_project).filter(
            Q(owner_id=normalized_actor) | Q(members__id=normalized_actor)
        ).exists()
        if membership is None or not project_access:
            raise PermissionError('Active tenant and project membership are required to propose a governed action.')

        existing = GovernedActionRequest.objects.filter(
            organization=organization,
            idempotency_key=key,
        ).first()
        if existing is not None:
            same_request = (
                str(existing.project_id) == normalized_project
                and str(existing.requested_by_id) == normalized_actor
                and existing.action_id == normalized_action
                and existing.entity_type == normalized_type
                and existing.entity_id == normalized_entity
                and int(existing.expected_version) == int(expected_version)
                and dict(existing.parameters_snapshot or {}) == payload
            )
            if not same_request:
                raise GovernedActionRequestConflict(
                    'Idempotency key was already used for a different governed action request in this organization.'
                )
            return GovernedActionRequestResult(existing, True)

        contract = get_action_contract(normalized_action)
        if contract is None:
            raise GovernedActionRequestError('Unknown governed action contract.')
        if contract.entity_type != normalized_type:
            raise GovernedActionRequestError('Governed action entity_type does not match its canonical ActionContract.')
        contract_snapshot = contract.model_dump(mode='json')
        contract_fingerprint = _sha({
            'contract_version': AGOM_CONTRACT_VERSION,
            'contract': contract_snapshot,
        })
        fingerprint = _sha({
            'contract_version': AGOM_CONTRACT_VERSION,
            'contract_fingerprint': contract_fingerprint,
            'project_id': normalized_project,
            'requested_by_id': normalized_actor,
            'action_id': normalized_action,
            'entity_type': normalized_type,
            'entity_id': normalized_entity,
            'expected_version': int(expected_version),
            'parameters': payload,
        })

        # Resolve the canonical entity only for a new proposal. An exact
        # idempotent replay returns the immutable historical request even if the
        # entity or current policy later changes.
        context = resolve_entity_capability_context(
            project_id=normalized_project,
            user_id=normalized_actor,
            entity_type=normalized_type,
            entity_id=normalized_entity,
        )
        if context.organization_id != str(organization.id):
            raise GovernedActionRequestError('Governed action request entity tenant does not match the project tenant.')

        row = GovernedActionRequest.objects.create(
            organization=organization,
            project_id=normalized_project,
            requested_by_id=normalized_actor,
            action_id=normalized_action,
            entity_type=normalized_type,
            entity_id=normalized_entity,
            expected_version=int(expected_version),
            idempotency_key=key,
            request_fingerprint=fingerprint,
            contract_version=AGOM_CONTRACT_VERSION,
            contract_policy_version=contract.policy_version,
            contract_snapshot=contract_snapshot,
            contract_fingerprint=contract_fingerprint,
            correlation_id=uuid.UUID(str(correlation_id)) if correlation_id else uuid.uuid4(),
            parameters_snapshot=payload,
        )
        return GovernedActionRequestResult(row, False)


def governed_action_request_view(result: GovernedActionRequestResult) -> dict[str, Any]:
    row = result.request
    return {
        'request_id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'requested_by_id': str(row.requested_by_id),
        'action_id': row.action_id,
        'entity_type': row.entity_type,
        'entity_id': row.entity_id,
        'expected_version': row.expected_version,
        'idempotency_key': row.idempotency_key,
        'request_fingerprint': row.request_fingerprint,
        'contract_version': row.contract_version,
        'contract_policy_version': row.contract_policy_version,
        'contract_fingerprint': row.contract_fingerprint,
        'correlation_id': row.correlation_id,
        'parameters': dict(row.parameters_snapshot or {}),
        'replayed': result.replayed,
        'created_at': row.created_at,
    }
