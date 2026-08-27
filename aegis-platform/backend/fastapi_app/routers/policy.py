from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.policy_engine import DEFAULT_POLICIES, evaluate_policy
from ..services.decision_action_orchestration import get_action

router = APIRouter()
security = HTTPBearer(auto_error=True)
_POLICIES: list[dict[str, Any]] = [dict(p) for p in DEFAULT_POLICIES]

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

@router.get("/policies")
async def policies(user: dict[str, Any] = Depends(require_user)):
    return {"items": sorted(_POLICIES, key=lambda p: (int(p.get("priority", 0)), int(p.get("version", 0))), reverse=True)}

@router.post("/policies")
async def create_policy(body: PolicyPayload, user: dict[str, Any] = Depends(require_user)):
    existing = next((p for p in _POLICIES if p["id"] == body.id), None)
    if existing:
        raise HTTPException(status_code=409, detail="Policy already exists")
    item = {**body.model_dump(), "version": 1, "updatedBy": str(user.get("id") or user.get("username") or "user")}
    _POLICIES.append(item)
    return item

@router.put("/policies/{policy_id}")
async def update_policy(policy_id: str, body: PolicyPayload, user: dict[str, Any] = Depends(require_user)):
    for index, existing in enumerate(_POLICIES):
        if existing["id"] == policy_id:
            item = {**body.model_dump(), "id": policy_id, "version": int(existing.get("version", 1)) + 1, "updatedBy": str(user.get("id") or user.get("username") or "user")}
            _POLICIES[index] = item
            return item
    raise HTTPException(status_code=404, detail="Policy not found")

@router.post("/policies/evaluate/{action_id}")
async def evaluate_action_policy(action_id: str, user: dict[str, Any] = Depends(require_user)):
    action = get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return {"actionId": action_id, "policy": evaluate_policy(action, _POLICIES)}
