from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.engine_capabilities import capability_for, list_capabilities

router = APIRouter()
security = HTTPBearer(auto_error=True)


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    user = await verify_token(credentials.credentials)
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/engine-capabilities")
async def engine_capabilities(user: dict = Depends(require_user)):
    return {"engines": list_capabilities()}


@router.get("/engine-capabilities/{engine}")
async def engine_capability(engine: str, user: dict = Depends(require_user)):
    return capability_for(engine)
