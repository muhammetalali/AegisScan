from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.intelligence_fabric import IntelligenceFabric, ProviderUnavailable
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

router = APIRouter()
security = HTTPBearer(auto_error=True)
fabric = IntelligenceFabric()


class Asset(BaseModel):
    id: str | None = None
    name: str | None = None
    product: str | None = None
    vendor: str | None = None
    version: str | None = None
    cpe: str | None = None


class EnrichRequest(BaseModel):
    cve_id: str = Field(min_length=8, max_length=32)
    assets: list[Asset] = Field(default_factory=list, max_length=500)


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/intelligence/providers")
async def providers(user: dict = Depends(require_user)):
    return {"providers": [{"id": key, "status": "configured"} for key in fabric.providers]}


@router.post("/intelligence/enrich")
async def enrich(body: EnrichRequest, user: dict = Depends(require_user)):
    try:
        result = await fabric.enrich(body.cve_id, [asset.model_dump() for asset in body.assets])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ProviderUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return result
