from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from typing import Any

from ..core.security import verify_token
from ..services.policy_engine import evaluate_policy, list_policies, save_policy
from ..services.policy_simulation import simulate_policy
from ..services.decision_action_orchestration import get_action

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
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
    return {"items": list_policies()}

@router.post("/policies", status_code=201)
async def create_policy(body: PolicyPayload, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    if any(p["id"] == body.id for p in list_policies()):
        raise HTTPException(status_code=409, detail="Policy already exists; use PUT to create a new version")
    return save_policy(body.model_dump(), actor)

@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, body: PolicyPayload, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("id") or user.get("username") or "user")
    if not any(p["id"] == policy_id for p in list_policies()):
        raise HTTPException(status_code=404, detail="Policy not found")
    payload = body.model_dump(); payload["id"] = policy_id
    return save_policy(payload, actor)

@router.post("/policies/evaluate/{action_id}")
async def evaluate_action_policy(action_id: str, user: dict[str, Any] = Depends(require_user)):
    action = get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return {"actionId": action_id, "policy": evaluate_policy(action)}

@router.post("/policies/simulate")
async def simulate(body: PolicySimulationPayload, user: dict[str, Any] = Depends(require_user)):
    action = get_action(body.action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    result = simulate_policy(action, body.policy.model_dump())
    return result
