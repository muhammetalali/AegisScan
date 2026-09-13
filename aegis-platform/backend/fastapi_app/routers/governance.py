from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from ..contracts.governed_responsibilities import (
    ActorAuthorityView,
    ResponsibilityAssignmentView,
    ResponsibilityChainView,
    ResponsibilityGrantRequest,
    ResponsibilityRevokeRequest,
    ResponsibilityRevocationView,
)
from ..core.dependencies import get_current_user
from ..services.decision_action_orchestration import get_action, list_actions
from ..services.governance_engine import enrich_governance, governance_metrics
from ..services.governed_operations import get_action_contract, registry_summary
from ..services.governed_responsibility_authority import (
    GovernedResponsibilityConflict,
    GovernedResponsibilityError,
    grant_responsibility,
    resolve_actor_authority,
    revoke_responsibility,
    verify_responsibility_event_chain,
)
from ..services.policy_engine import evaluate_policy, list_policies
from ..services.workflow_intelligence import enrich_action

router = APIRouter()


async def require_user(user=Depends(get_current_user)) -> dict[str, Any]:
    return user


def _actor_id(user: dict[str, Any]) -> str:
    actor = str(user.get('user_id') or user.get('id') or '')
    if not actor:
        raise HTTPException(status_code=401, detail='Authenticated user id is missing')
    return actor


def _raise_governed_error(exc: Exception) -> None:
    if isinstance(exc, GovernedResponsibilityConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, GovernedResponsibilityError):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise exc


def _assignment_view(result) -> ResponsibilityAssignmentView:
    item = result.assignment
    return ResponsibilityAssignmentView(
        assignment_id=str(item.id),
        organization_id=str(item.organization_id),
        project_id=str(item.project_id) if item.project_id else None,
        membership_id=str(item.membership_id),
        responsibility=item.responsibility,
        scope_kind=item.scope_kind,
        entity_type=item.entity_type,
        entity_id=item.entity_id,
        valid_from=item.valid_from,
        valid_until=item.valid_until,
        policy_version=item.policy_version,
        request_fingerprint=item.request_fingerprint,
        grant_fingerprint=item.grant_fingerprint,
        issued_by=str(item.issued_by_id),
        issued_at=item.issued_at,
        supersedes_assignment_id=str(item.supersedes_id) if item.supersedes_id else None,
        replayed=result.replayed,
    )


def _revocation_view(result) -> ResponsibilityRevocationView:
    item = result.revocation
    return ResponsibilityRevocationView(
        revocation_id=str(item.id),
        assignment_id=str(item.assignment_id),
        policy_version=item.policy_version,
        request_fingerprint=item.request_fingerprint,
        revocation_fingerprint=item.revocation_fingerprint,
        revoked_by=str(item.revoked_by_id),
        revoked_at=item.revoked_at,
        replayed=result.replayed,
    )


@router.get('/governance')
async def governance(user: dict[str, Any] = Depends(require_user)):
    actor = _actor_id(user)
    stored_actions = await sync_to_async(list_actions)(actor)
    actions = [enrich_action(item) for item in stored_actions]
    policies = await sync_to_async(list_policies)()
    items = [enrich_policy_governance(item, policies) for item in enrich_governance(actions)]
    metrics = governance_metrics(actions)
    metrics['policyControlled'] = len(items)
    return {'items': items, 'metrics': metrics}


def enrich_policy_governance(action: dict[str, Any], policies: list[dict[str, Any]]) -> dict[str, Any]:
    return {**action, 'policy': evaluate_policy(action, policies)}


@router.get('/governance/actions/{action_id}')
async def governance_action(action_id: str, user: dict[str, Any] = Depends(require_user)):
    actor = _actor_id(user)
    item = await sync_to_async(get_action)(action_id, actor)
    if item is None:
        raise HTTPException(status_code=404, detail='Action not found')
    action = enrich_action(item)
    policies = await sync_to_async(list_policies)()
    return {'actionId': action_id, 'governance': {**action.get('governance', {}), 'policy': evaluate_policy(action, policies)}}


@router.get('/governance/contracts')
async def governed_action_contracts(user: dict[str, Any] = Depends(require_user)):
    """Authenticated metadata only; this endpoint never grants authority."""
    _actor_id(user)
    return registry_summary()


@router.get('/governance/contracts/{action_id}')
async def governed_action_contract(action_id: str, user: dict[str, Any] = Depends(require_user)):
    _actor_id(user)
    contract = get_action_contract(action_id)
    if contract is None:
        raise HTTPException(status_code=404, detail='Governed action contract not found')
    return contract.model_dump(mode='json')


@router.post('/governance/responsibilities/grants', response_model=ResponsibilityAssignmentView)
async def governed_responsibility_grant(
    body: ResponsibilityGrantRequest,
    user: dict[str, Any] = Depends(require_user),
):
    actor = _actor_id(user)
    try:
        result = await sync_to_async(grant_responsibility)(
            organization_id=body.organization_id,
            actor_id=actor,
            membership_id=body.membership_id,
            responsibility=body.responsibility,
            scope_kind=body.scope_kind,
            reason=body.reason,
            idempotency_key=body.idempotency_key,
            project_id=body.project_id,
            entity_type=body.entity_type,
            entity_id=body.entity_id,
            valid_from=body.valid_from,
            valid_until=body.valid_until,
            supersedes_assignment_id=body.supersedes_assignment_id,
        )
    except (GovernedResponsibilityError, PermissionError) as exc:
        _raise_governed_error(exc)
    return _assignment_view(result)


@router.post('/governance/responsibilities/{assignment_id}/revoke', response_model=ResponsibilityRevocationView)
async def governed_responsibility_revoke(
    assignment_id: str,
    body: ResponsibilityRevokeRequest,
    user: dict[str, Any] = Depends(require_user),
):
    actor = _actor_id(user)
    try:
        result = await sync_to_async(revoke_responsibility)(
            assignment_id=assignment_id,
            actor_id=actor,
            reason=body.reason,
            idempotency_key=body.idempotency_key,
        )
    except (GovernedResponsibilityError, PermissionError) as exc:
        _raise_governed_error(exc)
    return _revocation_view(result)


@router.get('/governance/responsibilities/authority', response_model=ActorAuthorityView)
async def governed_responsibility_authority(
    organization_id: str,
    project_id: str | None = None,
    entity_type: str = '',
    entity_id: str = '',
    user: dict[str, Any] = Depends(require_user),
):
    actor = _actor_id(user)
    try:
        authority = await sync_to_async(resolve_actor_authority)(
            organization_id=organization_id,
            user_id=actor,
            project_id=project_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )
    except (GovernedResponsibilityError, PermissionError) as exc:
        _raise_governed_error(exc)
    return ActorAuthorityView(
        organization_id=authority.organization_id,
        project_id=authority.project_id,
        membership_id=authority.membership_id,
        role=authority.role,
        responsibilities=sorted(authority.responsibilities),
    )


@router.get('/governance/responsibilities/chain', response_model=ResponsibilityChainView)
async def governed_responsibility_chain(
    organization_id: str,
    user: dict[str, Any] = Depends(require_user),
):
    actor = _actor_id(user)
    try:
        # Membership check prevents cross-tenant chain enumeration.
        await sync_to_async(resolve_actor_authority)(organization_id=organization_id, user_id=actor)
        result = await sync_to_async(verify_responsibility_event_chain)(organization_id=organization_id)
    except (GovernedResponsibilityError, PermissionError) as exc:
        _raise_governed_error(exc)
    return ResponsibilityChainView(**result)
