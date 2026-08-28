from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.risk_context_fusion import RiskContextFusion

router = APIRouter()
security = HTTPBearer(auto_error=True)
engine = RiskContextFusion()


class RiskContextRequest(BaseModel):
    observations: dict[str, dict[str, object]] = Field(default_factory=dict, max_length=64)
    external_intelligence: list[dict[str, object]] = Field(default_factory=list, max_length=200)
    remediation: dict[str, object] = Field(default_factory=dict)
    behavioral_anomaly: float = Field(default=0.0, ge=0.0, le=1.0)
    newly_exposed_ports: int = Field(default=0, ge=0, le=10000)
    critical_service_exposure: bool = False
    business_impact: float = Field(default=0.0, ge=0.0, le=100.0)


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    user = await verify_token(credentials.credentials)
    if not user:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.post("/risk/context")
async def evaluate_context(body: RiskContextRequest, user: dict = Depends(require_user)):
    result = engine.evaluate(
        base_observations=body.observations,
        external_intelligence=body.external_intelligence,
        remediation=body.remediation,
        behavioral_anomaly=body.behavioral_anomaly,
        newly_exposed_ports=body.newly_exposed_ports,
        critical_service_exposure=body.critical_service_exposure,
        business_impact=body.business_impact,
    )
    return {
        "fusion": result.fusion,
        "dynamic_risk": result.dynamic,
        "risk_delta": result.risk_delta,
        "decision": result.decision,
        "lineage": list(result.lineage),
        "engine": "aegis-risk-context-v1",
    }
