from __future__ import annotations

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request

from ..contracts.governed_actions import GovernedActionExecuteRequest, GovernedActionExecutionView
from ..core.dependencies import get_current_user
from ..services.campaign_objective_assurance import CampaignAssuranceError, StaleCampaignVersion, StaleObjectiveVersion
from ..services.entity_capability_adapters import EntityCapabilityError, EntityCapabilityNotFound
from ..services.finding_closure import FindingClosureError, StaleFindingClosureVersion
from ..services.finding_confirmation import FindingConfirmationError, StaleFindingConfirmationVersion
from ..services.governed_action_executor import GovernedActionBlocked, GovernedActionConflict, GovernedActionError, execute_governed_action, governed_action_view

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
        StaleCampaignVersion,
        StaleObjectiveVersion,
        StaleFindingConfirmationVersion,
        StaleFindingClosureVersion,
    )):
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if isinstance(exc, (
        GovernedActionError,
        EntityCapabilityError,
        CampaignAssuranceError,
        FindingConfirmationError,
        FindingClosureError,
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
            correlation_id=body.correlation_id,
            ip_address=_request_ip(request),
            user_agent=request.headers.get('user-agent', ''),
            session_id=request.cookies.get('sessionid', ''),
        )
        return GovernedActionExecutionView(**governed_action_view(result))
    except Exception as exc:  # noqa: BLE001
        translate_governed_action_error(exc)
