from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Any

from ..core.security import verify_token
from ..services.autonomous_triage import triage_graph
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.assurance_correlation import correlate_all
from ..services.graph_intelligence import analyze_graph
from ..services.security_decision import build_decision_pack

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@router.get("/decision-pack")
async def decision_pack(user: dict[str, Any] = Depends(require_user)):
    from .validations import _store
    correlations = correlate_all(_store)
    graph = analyze_graph(build_assurance_graph(_store, correlations))
    triage = triage_graph(graph)
    return build_decision_pack({"items": triage.get("priorities", []), "generatedAt": None})
