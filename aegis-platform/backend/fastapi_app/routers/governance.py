from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.decision_action_orchestration import list_actions, get_action
from ..services.workflow_intelligence import enrich_action
from ..services.governance_engine import evaluate_governance, enrich_governance, governance_metrics

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@router.get("/governance")
async def governance(user: dict[str, Any] = Depends(require_user)):
    actions = [enrich_action(item) for item in list_actions()]
    return {"items": enrich_governance(actions), "metrics": governance_metrics(actions)}

@router.get("/governance/actions/{action_id}")
async def governance_action(action_id: str, user: dict[str, Any] = Depends(require_user)):
    from fastapi import HTTPException
    item = get_action(action_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Action not found")
    return {"actionId": action_id, "governance": evaluate_governance(enrich_action(item))}
