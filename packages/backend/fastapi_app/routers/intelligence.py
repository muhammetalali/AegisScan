from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.autonomous_assurance import propose_remediation
from ..services.behavioral_terrain import build_fingerprint
from ..services.correlation_intelligence import correlate
from ..services.external_intelligence import ExternalIntelligenceFabric
from ..services.intelligence_fabric import IntelligenceFabric, ProviderUnavailable
from ..services.risk_engine import assess_risk

router = APIRouter()
security = HTTPBearer(auto_error=True)
fabric = IntelligenceFabric()
external_fabric = ExternalIntelligenceFabric()


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


class BehavioralRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=200)
    baseline: dict[str, float] = Field(default_factory=dict, max_length=100)
    observed: dict[str, float] = Field(default_factory=dict, max_length=100)


class CorrelationRequest(BaseModel):
    entity_id: str = Field(min_length=1, max_length=200)
    evidence: list[dict[str, object]] = Field(default_factory=list, max_length=500)


class RemediationRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=200)
    evidence: list[dict[str, object]] = Field(default_factory=list, max_length=100)


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
    provider_status = result.get("provider_status", {})
    source_count = sum(status == "ok" for status in provider_status.values()) if provider_status else 4
    assessment = assess_risk(cvss=result.get("cvss"), epss=result.get("epss"), kev=bool(result.get("kev")), matched_assets=len(result.get("matched_assets") or []), published=result.get("published"), source_count=source_count)
    result.update({"risk_score": assessment.score, "severity": assessment.severity, "confidence": assessment.confidence, "risk_factors": list(assessment.factors), "risk_engine": "aegis-risk-v1"})
    return result


@router.post("/intelligence/behavioral-fingerprint")
async def behavioral(body: BehavioralRequest, user: dict = Depends(require_user)):
    return build_fingerprint(body.asset_id, body.baseline, body.observed).__dict__


@router.post("/intelligence/correlate")
async def correlation(body: CorrelationRequest, user: dict = Depends(require_user)):
    result = correlate(body.entity_id, body.evidence)
    return {"entity_id": result.entity_id, "confidence": result.confidence, "relationships": list(result.relationships), "conflicts": list(result.conflicts)}


@router.post("/intelligence/external")
async def external(body: dict[str, str], user: dict = Depends(require_user)):
    indicator = str(body.get("indicator", "")).strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="indicator is required")
    return await external_fabric.search(indicator)


@router.post("/intelligence/remediation-proposal")
async def remediation(body: RemediationRequest, user: dict = Depends(require_user)):
    proposal = propose_remediation(body.finding_id, body.evidence, body.target)
    return proposal.__dict__
