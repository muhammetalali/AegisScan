from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..services.itsm_provider_health import check_all_providers, check_provider
from ..core.security import verify_token
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

router = APIRouter()
security = HTTPBearer(auto_error=False)


async def _staff_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not user.get("is_staff"):
        raise HTTPException(status_code=403, detail="Staff access required")
    return user


@router.get("/orchestration/providers/health")
async def providers_health(_user=Depends(_staff_user)):
    result = await check_all_providers()
    if result["status"] != "healthy":
        raise HTTPException(status_code=503, detail=result)
    return result


@router.get("/orchestration/providers/{provider}/health")
async def provider_health(provider: str, _user=Depends(_staff_user)):
    if provider not in {"jira", "servicenow"}:
        raise HTTPException(status_code=404, detail="Unsupported provider")
    result = await check_provider(provider)
    if result["status"] not in {"healthy", "not_configured"}:
        raise HTTPException(status_code=503, detail=result)
    return result
