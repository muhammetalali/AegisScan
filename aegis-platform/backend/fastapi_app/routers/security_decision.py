from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Any

from ..core.security import verify_token
from ..services.autonomous_triage import build_triage
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.assurance_correlation import correlate_all
from ..services.graph_intelligence import analyze_graph
from ..services.security_decision import build_decision_pack
from .assurance_graph import _load_validations

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/decision-pack")
async def decision_pack(user: dict[str, Any] = Depends(require_user)):
    user_id = str(user.get("user_id") or user.get("id") or "")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user id is missing")
    validations = await _load_validations(user_id)
    correlations = correlate_all(validations)
    graph = analyze_graph(build_assurance_graph(validations, correlations))
    triage = build_triage(graph)
    return build_decision_pack(triage)
