from fastapi import APIRouter, Depends, HTTPException
from typing import Any

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all, correlate_validation
from ..services.assurance_graph_aggregator import build_assurance_graph

router = APIRouter()

async def current_user(credentials: Any = Depends(lambda: None)):
    # Authentication is enforced at the application boundary when this router is wired.
    return credentials

@router.get("/graph")
async def assurance_graph():
    from .validations import _store
    correlations = correlate_all(_store)
    return build_assurance_graph(_store, correlations)

@router.get("/graph/validations/{validation_id}")
async def assurance_graph_validation(validation_id: str):
    from .validations import _store
    validation = _store.get(validation_id)
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    correlation = correlate_validation(validation_id, validation)
    return build_assurance_graph({validation_id: validation}, {"items": correlation["conflicts"]})
