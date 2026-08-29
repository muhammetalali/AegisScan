from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Any, Optional

from ..core.security import verify_token
from ..services.assurance_correlation import correlate_all, correlate_validation
from ..services.validation_state import _store

router = APIRouter()
security = HTTPBearer(auto_error=False)


class AssuranceSummary(BaseModel):
    conflicts: int
    signals: int
    sources: int
    agreement: int
    confidence: int


async def require_assurance_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/correlations/conflicts")
async def list_conflicts(limit: int = Query(100, ge=1, le=500), _user=Depends(require_assurance_user)):
    result = correlate_all(_store)
    result["items"] = result["items"][:limit]
    return result


@router.get("/correlations/summary", response_model=AssuranceSummary)
async def correlation_summary(_user=Depends(require_assurance_user)):
    result = correlate_all(_store)
    return result["summary"]


@router.get("/correlations/validations/{validation_id}")
async def validation_correlation(validation_id: str, _user=Depends(require_assurance_user)):
    validation: Optional[dict[str, Any]] = _store.get(validation_id)
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return correlate_validation(validation_id, validation)
