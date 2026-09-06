from __future__ import annotations

from typing import Any
from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.decision_action_orchestration import list_actions, get_action
from ..services.workflow_intelligence import enrich_action
from ..services.governance_engine import enrich_governance, governance_metrics
from ..services.policy_engine import evaluate_policy

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def enrich_policy_governance(action: dict[str, Any]) -> dict[str, Any]:
    return {**action, "policy": evaluate_policy(action)}

@router.get("/governance")
async def governance(user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    stored_actions = await sync_to_async(list_actions)(actor)
    actions = [enrich_action(item) for item in stored_actions]
    items = [enrich_policy_governance(item) for item in enrich_governance(actions)]
    metrics = governance_metrics(actions)
    metrics["policyControlled"] = len(items)
    return {"items": items, "metrics": metrics}

@router.get("/governance/actions/{action_id}")
async def governance_action(action_id: str, user: dict[str, Any] = Depends(require_user)):
    actor = str(user.get("user_id") or user.get("id") or user.get("username") or "")
    if not actor:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    item = await sync_to_async(get_action)(action_id, actor)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    action = enrich_action(item)
    return {"actionId": action_id, "governance": {**action.get("governance", {}), "policy": evaluate_policy(action)}}
