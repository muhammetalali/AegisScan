from __future__ import annotations

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request

from ..contracts.governed_actions import (
    GovernedActionExecuteRequest,
    GovernedActionExecutionView,
    GovernedActionRequestCreate,
    GovernedActionRequestView,
)
from ..core.dependencies import get_current_user
from ..services.asset_authorization_governance import (
    AssetAuthorizationConflict,
    AssetAuthorizationGovernanceError,
    StaleAssetAuthorizationVersion,
)
from ..services.campaign_objective_assurance import CampaignAssuranceError, StaleCampaignVersion, StaleObjectiveVersion
from ..services.entity_capability_adapters import EntityCapabilityError, EntityCapabilityNotFound
from ..services.finding_closure import FindingClosureError, StaleFindingClosureVersion
from ..services.finding_confirmation import FindingConfirmationError, StaleFindingConfirmationVersion
from ..services.finding_disposition import FindingDispositionError, StaleFindingDispositionVersion
from ..services.governed_action_executor import GovernedActionBlocked, GovernedActionConflict, GovernedActionError, execute_governed_action, governed_action_view
from ..services.security_operations import StaleCaseVersion
from ..services.soc_closure_governance import ClosureGovernanceError
from ..services.governed_action_requests import (
    GovernedActionRequestConflict,
    GovernedActionRequestError,
    create_governed_action_request,
    governed_action_request_view,
)

router = APIRouter()


def _actor_id(user):
    actor = str(user.get('user_id') or user.get('id') or '').strip()
    if not actor:
        raise HTTPException(status_code=401, detail='Authenticated user id is missing')
    return actor


def _request_ip(request: Request) -> str:
    value = str(request.client.host if request.client else '').strip()
    return value if value.count('.') == 3 else '127.0.0.1'


def translate_governed_action_error(exc: Exception) -> None:
    if isinstance(exc, EntityCapabilityNotFound):
        raise HTTPException(status_code=404, detail='Governed action target not found') from exc
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if isinstance(exc, GovernedActionBlocked):
        raise HTTPException(status_code=409, detail={'code': exc.reason_code, 'reason': exc.reason, 'missing_requirements': exc.missing_requirements}) from exc
    if isinstance(exc, (
        GovernedActionConflict,
        AssetAuthorizationConflict,
        StaleAssetAuthorizationVersion,
        GovernedActionRequestConflict,
        StaleCampaignVersion,
        StaleObjectiveVersion,
        StaleFindingConfirmationVersion,
        StaleFindingClosureVersion,
        StaleFindingDispositionVersion,
        StaleCaseVersion,
    )):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, (
        GovernedActionError,
        AssetAuthorizationGovernanceError,
        GovernedActionRequestError,
        EntityCapabilityError,
        CampaignAssuranceError,
        FindingConfirmationError,
        FindingClosureError,
        FindingDispositionError,
        ClosureGovernanceError,
    )):
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    raise exc


@router.post('/actions/execute', response_model=GovernedActionExecutionView)
async def execute_governed_action_api(body: GovernedActionExecuteRequest, request: Request, current_user=Depends(get_current_user)):
    try:
        result = await sync_to_async(execute_governed_action)(
            action_id=body.action_id,
            project_id=body.project_id,
            actor_id=_actor_id(current_user),
            entity_type=body.entity_type,
            entity_id=body.entity_id,
            expected_version=body.expected_version,
            idempotency_key=body.idempotency_key,
            parameters=body.parameters,
            request_id=str(body.request_id) if body.request_id else None,
            correlation_id=body.correlation_id,
            ip_address=_request_ip(request),
            user_agent=request.headers.get('user-agent', ''),
            session_id=request.cookies.get('sessionid', ''),
        )
        return GovernedActionExecutionView(**governed_action_view(result))
    except Exception as exc:  # noqa: BLE001
        translate_governed_action_error(exc)


@router.post('/actions/requests', response_model=GovernedActionRequestView, status_code=201)
async def create_governed_action_request_api(
    body: GovernedActionRequestCreate,
    current_user=Depends(get_current_user),
):
    try:
        result = await sync_to_async(create_governed_action_request)(
            action_id=body.action_id,
            project_id=body.project_id,
            requested_by_id=_actor_id(current_user),
            entity_type=body.entity_type,
            entity_id=body.entity_id,
            expected_version=body.expected_version,
            idempotency_key=body.idempotency_key,
            parameters=body.parameters,
            correlation_id=body.correlation_id,
        )
        return GovernedActionRequestView(**governed_action_request_view(result))
    except Exception as exc:  # noqa: BLE001
        translate_governed_action_error(exc)
