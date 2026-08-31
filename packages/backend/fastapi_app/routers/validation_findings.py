from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..core.security import verify_token
from ..services.validation_state import _get_redis, get_validation

router = APIRouter()
security = HTTPBearer(auto_error=False)


async def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def ensure_owner(item: dict, user: dict) -> None:
    if item.get("owner_id") != str(user.get("id")) and not user.get("is_superuser"):
        raise HTTPException(status_code=404, detail="Validation not found")


@router.get("/validations/{validation_id}/findings")
async def validation_findings(validation_id: str, user: dict = Depends(current_user)):
    """Return findings emitted by a real validation execution from its authoritative Redis state."""
    item = get_validation(validation_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    ensure_owner(item, user)
    findings = item.get("results", {}).get("findings", [])
    if not isinstance(findings, list):
        raise HTTPException(status_code=503, detail="Validation findings store returned invalid data")
    return {
        "validation_id": validation_id,
        "status": item.get("status"),
        "count": len(findings),
        "findings": findings,
    }


@router.get("/findings/{finding_id}")
async def finding_detail(finding_id: str, user: dict = Depends(current_user)):
    """Find a finding emitted by a validation while enforcing tenant ownership."""
    try:
        client = _get_redis()
        for key in client.scan_iter(match="aegis:validation:*"):
            raw = client.get(key)
            if not raw:
                continue
            item = json.loads(raw)
            if not isinstance(item, dict):
                continue
            if item.get("owner_id") != str(user.get("id")) and not user.get("is_superuser"):
                continue
            for finding in item.get("results", {}).get("findings", []):
                if isinstance(finding, dict) and str(finding.get("id")) == finding_id:
                    return {
                        "validation_id": item.get("id"),
                        "status": item.get("status"),
                        "finding": finding,
                    }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Validation findings store is unavailable") from exc
    raise HTTPException(status_code=404, detail="Finding not found")
