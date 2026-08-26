from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Any

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all, correlate_validation
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.graph_intelligence import analyze_graph

router = APIRouter()
security = HTTPBearer(auto_error=True)

async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict[str, Any]:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

def _build(validations: dict[str, dict[str, Any]], correlations: dict[str, Any]) -> dict[str, Any]:
    return analyze_graph(build_assurance_graph(validations, correlations))

@router.get("/graph")
async def assurance_graph(user: dict[str, Any] = Depends(require_user)):
    from .validations import _store
    correlations = correlate_all(_store)
    return _build(_store, correlations)

@router.get("/graph/validations/{validation_id}")
async def assurance_graph_validation(validation_id: str, user: dict[str, Any] = Depends(require_user)):
    from .validations import _store
    validation = _store.get(validation_id)
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    correlation = correlate_validation(validation_id, validation)
    return _build({validation_id: validation}, {"items": correlation["conflicts"]})
