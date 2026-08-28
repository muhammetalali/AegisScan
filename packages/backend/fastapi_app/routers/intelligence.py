from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..advanced_intelligence import ADIProvider, BTEProvider, CorrelationEngine, ScannerAdapter
from ..core.security import verify_token
from ..services.autonomous_assurance import propose_remediation
from ..services.behavioral_terrain import build_fingerprint
from ..services.dynamic_risk_engine import DynamicRiskModel
from ..services.external_intelligence import ExternalIntelligenceFabric
from ..services.fusion_engine import FusionEngine
from ..services.intelligence_fabric import IntelligenceFabric, ProviderUnavailable
from ..services.risk_engine import assess_risk

router = APIRouter()
security = HTTPBearer(auto_error=True)
fabric = IntelligenceFabric()
external_fabric = ExternalIntelligenceFabric()
advanced_correlation = CorrelationEngine()
bte_provider = BTEProvider()
adi_provider = ADIProvider()
scanner_adapter = ScannerAdapter()
fusion_engine = FusionEngine()
dynamic_risk_model = DynamicRiskModel()


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


class FusionRequest(BaseModel):
    observations: dict[str, dict[str, object]] = Field(default_factory=dict, max_length=32)


class DynamicRiskRequest(BaseModel):
    base_score: float = Field(ge=0.0, le=100.0)
    behavioral_anomaly: float = Field(default=0.0, ge=0.0, le=1.0)
    newly_exposed_ports: int = Field(default=0, ge=0, le=10000)
    critical_service_exposure: bool = False
    validated_exploitation: bool = False
    business_impact: float = Field(default=0.0, ge=0.0, le=100.0)


class BehavioralRequest(BaseModel):
    asset_id: str = Field(min_length=1, max_length=200)
    baseline: dict[str, float] = Field(default_factory=dict, max_length=100)
    observed: dict[str, float] = Field(default_factory=dict, max_length=100)


class CorrelationRequest(BaseModel):
    entity_id: str = Field(min_length=1, max_length=200)
    evidence: list[dict[str, object]] = Field(default_factory=list, max_length=500)


class AdvancedCorrelationRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    evidence: list[dict[str, object]] = Field(default_factory=list, max_length=500)


class ScannerRequest(BaseModel):
    tool: str = Field(min_length=2, max_length=32)
    findings: list[dict[str, object]] = Field(default_factory=list, max_length=1000)


class BTERequest(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    behavioral_signals: dict[str, object] = Field(default_factory=dict, max_length=100)
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)


class ADIRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    approved_cti: list[dict[str, object]] = Field(default_factory=list, max_length=500)


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
    core = [{"id": key, "status": "configured", "mode": "live-http"} for key in fabric.providers]
    external = []
    for provider in external_fabric.providers:
        name = provider.name
        if name == "greynoise":
            status = "configured" if __import__("os").getenv("GREYNOISE_API_KEY") else "not_configured"
        elif name == "shodan":
            status = "configured" if __import__("os").getenv("SHODAN_API_KEY") else "not_configured"
        elif name == "github_advisory":
            status = "available"
        else:
            status = "disabled_by_policy"
        external.append({"id": name, "status": status, "mode": "live-http" if name != "dark-intel-disabled" else "blocked"})
    return {"providers": core + external + [
        {"id": "bte", "status": "telemetry-only"},
        {"id": "adi", "status": "approved-feed-only"},
        {"id": "fusion", "status": "active"},
        {"id": "dynamic-risk", "status": "active"},
    ]}


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
    observations = {name: {"available": True} for name, status in provider_status.items() if status == "ok"}
    observations["nvd"] = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": result.get("cvss")}}]}} if result.get("cvss") is not None else {}
    observations["epss"] = {"epss": result.get("epss")} if result.get("epss") is not None else {}
    observations["cisa_kev"] = {"known": True} if result.get("kev") else {}
    fusion = fusion_engine.fuse(observations)
    assessment = assess_risk(cvss=result.get("cvss"), epss=result.get("epss"), kev=bool(result.get("kev")), matched_assets=len(result.get("matched_assets") or []), published=result.get("published"), source_count=source_count, exposure=1.0 if result.get("matched_assets") else 0.0)
    result.update({"risk_score": assessment.score, "severity": assessment.severity, "confidence": assessment.confidence, "risk_factors": list(assessment.factors), "risk_lineage": list(assessment.lineage), "risk_prediction": assessment.prediction, "risk_decision_id": assessment.decision_id, "risk_engine": "aegis-risk-v2", "fusion": {"score": fusion.score, "confidence": fusion.confidence, "rationale": fusion.rationale, "corroborated_sources": list(fusion.corroborated_sources), "conflicts": list(fusion.conflicts), "lineage": list(fusion.lineage)}})
    return result


@router.post("/intelligence/fusion")
async def fusion(body: FusionRequest, user: dict = Depends(require_user)):
    result = fusion_engine.fuse(body.observations)
    return {"score": result.score, "confidence": result.confidence, "rationale": result.rationale, "corroborated_sources": list(result.corroborated_sources), "conflicts": list(result.conflicts), "lineage": list(result.lineage)}


@router.post("/intelligence/risk/dynamic")
async def dynamic_risk(body: DynamicRiskRequest, user: dict = Depends(require_user)):
    result = dynamic_risk_model.assess(base_score=body.base_score, behavioral_anomaly=body.behavioral_anomaly, newly_exposed_ports=body.newly_exposed_ports, critical_service_exposure=body.critical_service_exposure, validated_exploitation=body.validated_exploitation, business_impact=body.business_impact)
    return {"score": result.score, "severity": result.severity, "adjustments": list(result.adjustments), "rationale": result.rationale, "assessed_at": result.assessed_at, "engine": "aegis-dynamic-risk-v1"}


@router.post("/intelligence/behavioral-fingerprint")
async def behavioral(body: BehavioralRequest, user: dict = Depends(require_user)):
    return build_fingerprint(body.asset_id, body.baseline, body.observed).__dict__


@router.post("/intelligence/bte")
async def bte(body: BTERequest, user: dict = Depends(require_user)):
    evidence = await bte_provider.collect(body.subject, body.model_dump())
    return {"subject": body.subject, "evidence": [item.__dict__ for item in evidence]}


@router.post("/intelligence/adi")
async def adi(body: ADIRequest, user: dict = Depends(require_user)):
    evidence = await adi_provider.collect(body.subject, body.model_dump())
    return {"subject": body.subject, "evidence": [item.__dict__ for item in evidence], "mode": "approved-feed-only"}


@router.post("/intelligence/correlate")
async def correlation(body: CorrelationRequest, user: dict = Depends(require_user)):
    result = correlate(body.entity_id, body.evidence)
    return {"entity_id": result.entity_id, "confidence": result.confidence, "relationships": list(result.relationships), "conflicts": list(result.conflicts)}


@router.post("/intelligence/correlate/v2")
async def correlation_v2(body: AdvancedCorrelationRequest, user: dict = Depends(require_user)):
    from ..services.advanced_intelligence import Evidence
    evidence = [Evidence(evidence_id=str(x.get("evidence_id", "")), source=str(x.get("source", "unknown")), kind=str(x.get("kind", "unknown")), subject=str(x.get("subject", body.subject)), confidence=max(0.0, min(1.0, float(x.get("confidence", 0.5)))), observed_at=str(x.get("observed_at", "")), attributes=dict(x.get("attributes", {})) if isinstance(x.get("attributes", {}), dict) else {}) for x in body.evidence]
    return advanced_correlation.correlate(body.subject, evidence)


@router.post("/intelligence/scanners/normalize")
async def normalize_scanner(body: ScannerRequest, user: dict = Depends(require_user)):
    try:
        normalized = scanner_adapter.normalize(body.tool, body.findings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"tool": body.tool.lower(), "count": len(normalized), "evidence": [item.__dict__ for item in normalized]}


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
