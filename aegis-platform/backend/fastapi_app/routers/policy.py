from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any

from ..core.dependencies import get_current_user, require_permission
from ..services.policy_engine import evaluate_policy, list_policies, save_policy
from ..services.policy_simulation import simulate_policy
from ..services.decision_action_orchestration import get_action
from django_project.users.models import Permission

router = APIRouter()


async def require_user(user=Depends(get_current_user)) -> dict[str, Any]:
    return user

class PolicyPayload(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    enabled: bool = True
    priority: int = Field(default=50, ge=0, le=1000)
    when: dict[str, Any] = Field(default_factory=dict)
    actions: dict[str, Any] = Field(default_factory=dict)

class PolicySimulationPayload(BaseModel):
    action_id: str = Field(min_length=1, max_length=256)
    policy: PolicyPayload

@router.get("/policies")
async def policies(user: dict[str, Any] = Depends(require_user)):
    return {"items": await sync_to_async(list_policies)()}

@router.post("/policies", status_code=201)
async def create_policy(body: PolicyPayload, user: dict[str, Any] = Depends(require_permission(Permission.SYSTEM_SETTINGS))):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    try:
        return await sync_to_async(save_policy)(body.model_dump(), actor, False)
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Policy already exists; use PUT to create a new version")

@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, body: PolicyPayload, user: dict[str, Any] = Depends(require_permission(Permission.SYSTEM_SETTINGS))):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    if not await sync_to_async(_is_policy_administrator)(actor):
        raise HTTPException(status_code=403, detail="Policy administration permission required")
    payload = body.model_dump(); payload["id"] = policy_id
    try:
        return await sync_to_async(save_policy)(payload, actor, True)
    except KeyError:
        raise HTTPException(status_code=404, detail="Policy not found")

@router.post("/policies/evaluate/{action_id}")
async def evaluate_action_policy(action_id: str, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    action = await sync_to_async(get_action)(action_id, actor)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    policies = await sync_to_async(list_policies)()
    return {"actionId": action_id, "policy": evaluate_policy(action, policies)}

@router.post("/policies/simulate")
async def simulate(body: PolicySimulationPayload, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    action = await sync_to_async(get_action)(body.action_id, actor)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    result = await sync_to_async(simulate_policy)(action, body.policy.model_dump())
    return result
