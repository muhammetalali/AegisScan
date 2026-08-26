from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Any, Optional

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all, correlate_validation

router = APIRouter()


class AssuranceSummary(BaseModel):
    conflicts: int
    signals: int
    sources: int
    agreement: int
    confidence: int


@router.get("/correlations/conflicts")
async def list_conflicts(limit: int = Query(100, ge=1, le=500)):
    from .validations import _store
    result = correlate_all(_store)
    result["items"] = result["items"][:limit]
    return result


@router.get("/correlations/summary", response_model=AssuranceSummary)
async def correlation_summary():
    from .validations import _store
    result = correlate_all(_store)
    return result["summary"]


@router.get("/correlations/validations/{validation_id}")
async def validation_correlation(validation_id: str):
    from .validations import _store
    validation: Optional[dict[str, Any]] = _store.get(validation_id)
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return correlate_validation(validation_id, validation)
