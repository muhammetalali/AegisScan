from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi.concurrency import run_in_threadpool

from django_project.security_sessions import services as session_service
from django_project.security_sessions.models import SecurityTestSession

from .dynamic_risk_engine import DynamicRiskModel
from .engine_adapters import execute_engine
from .external_intelligence import ExternalIntelligenceFabric
from .fusion_engine import FusionEngine
from .intelligence_fabric import IntelligenceFabric
from .remediation_validation import RemediationValidationSuite


class AssuranceRiskPipeline:
    """Correlate vulnerability, dependency, external CTI, remediation and runtime context."""

    def __init__(self, *, intelligence=None, external=None, fusion=None, dynamic_risk=None, remediation=None) -> None:
        self.intelligence = intelligence or IntelligenceFabric()
        self.external = external or ExternalIntelligenceFabric()
        self.fusion = fusion or FusionEngine()
        self.dynamic_risk = dynamic_risk or DynamicRiskModel()
        self.remediation = remediation or RemediationValidationSuite()

    @staticmethod
    def _session_owner(session_id: UUID | str) -> str:
        session = SecurityTestSession.objects.only("initiated_by_id").get(pk=session_id)
        return str(session.initiated_by_id)

    async def _record(self, session_id: UUID | str | None, event_type: str, *, target: str = "", action: str = "", status: str = "success", data: dict[str, Any] | None = None) -> None:
        if session_id is None:
            return
        owner_id = await run_in_threadpool(self._session_owner, session_id)
        await run_in_threadpool(
            session_service.append_evidence,
            session_id=session_id,
            user_id=owner_id,
            event_type=event_type,
            capability="passive_validate",
            target=target,
            action=action,
            status=status,
            data=data or {},
        )

    async def assess(
        self, *, indicator: str, cve_id: str | None = None, assets: list[dict[str, Any]] | None = None,
        behavioral_anomaly: float = 0.0, newly_exposed_ports: int = 0,
        critical_service_exposure: bool = False, business_impact: float = 0.0,
        validated_exploitation: bool = False, remediation_candidate: dict[str, Any] | None = None,
        remediation_tools: list[str] | None = None, remediation_timeout: int = 180,
        dependency_workspace: str | None = None,
        dependency_manifest: str | None = None,
        dependency_filename: str | None = None,
        session_id: UUID | str | None = None,
    ) -> dict[str, Any]:
        await self._record(session_id, "assurance.assessment.started", target=indicator, action="assess", data={"cve_id": cve_id})
        external = await self.external.search(indicator)
        vulnerability = await self.intelligence.enrich(cve_id, assets or []) if cve_id else None
        remediation_result = None
        if remediation_candidate is not None:
            remediation_result = await self.remediation.validate_workspace(
                remediation_candidate, tools=remediation_tools, timeout=remediation_timeout
            )

        dependency_result = None
        if dependency_manifest or dependency_workspace:
            dependency_extra = {
                "dependency_manifest": dependency_manifest,
                "dependency_filename": dependency_filename,
                "workspace": dependency_workspace,
            }
            dependency_result = await execute_engine(
                "dependency_risk", "code", dependency_workspace or "dependency-workspace", dependency_extra
            )

        observations: dict[str, dict[str, Any]] = {}
        if vulnerability:
            if vulnerability.get("cvss") is not None:
                observations["nvd"] = {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": vulnerability["cvss"]}}]}}
            if vulnerability.get("epss") is not None:
                observations["epss"] = {"epss": vulnerability["epss"]}
            if vulnerability.get("kev"):
                observations["cisa_kev"] = {"known": True}
        if external.get("items"):
            observations["external_intelligence"] = external
        if dependency_result is not None:
            dependency_metrics = dependency_result.metrics if isinstance(dependency_result.metrics, dict) else {}
            observations["dependency_risk"] = {
                **dependency_metrics,
                "status": dependency_result.status,
                "error": dependency_result.error,
                "findings_count": len(dependency_result.findings),
            }
            if dependency_result.evidence:
                observations["dependency_risk"]["evidence_count"] = len(dependency_result.evidence)
        if remediation_result is not None:
            observations["remediation_validation"] = remediation_result

        fusion = self.fusion.fuse(observations)
        external_ports = self._shodan_ports(external)
        derived_ports = max(newly_exposed_ports, external_ports)
        derived_exploitation = validated_exploitation or bool(vulnerability and vulnerability.get("kev"))
        dynamic = self.dynamic_risk.assess(
            base_score=fusion.score,
            behavioral_anomaly=behavioral_anomaly,
            newly_exposed_ports=derived_ports,
            critical_service_exposure=critical_service_exposure,
            validated_exploitation=derived_exploitation,
            business_impact=business_impact,
        )

        remediation_priority = self._remediation_priority(dynamic.score, fusion.confidence)
        result = {
            "session_id": str(session_id) if session_id else None,
            "indicator": indicator,
            "cve_id": cve_id,
            "vulnerability": vulnerability,
            "external_intelligence": external,
            "dependency_intelligence": {
                "status": dependency_result.status,
                "findings": dependency_result.findings,
                "evidence": dependency_result.evidence,
                "metrics": dependency_result.metrics,
                "error": dependency_result.error,
            } if dependency_result is not None else None,
            "remediation_validation": remediation_result,
            "fusion": {
                "score": fusion.score, "confidence": fusion.confidence, "rationale": fusion.rationale,
                "corroborated_sources": list(fusion.corroborated_sources), "conflicts": list(fusion.conflicts),
                "lineage": list(fusion.lineage),
            },
            "dynamic_risk": {
                "score": dynamic.score, "severity": dynamic.severity, "adjustments": list(dynamic.adjustments),
                "rationale": dynamic.rationale, "assessed_at": dynamic.assessed_at,
            },
            "decision": {
                "base_score": fusion.score, "final_score": dynamic.score, "severity": dynamic.severity,
                "confidence": fusion.confidence, "derived_newly_exposed_ports": derived_ports,
                "derived_validated_exploitation": derived_exploitation,
                "remediation_priority": remediation_priority,
            },
        }
        await self._record(
            session_id,
            "assurance.assessment.completed",
            target=indicator,
            action="assess",
            data={
                "fusion_score": fusion.score,
                "fusion_confidence": fusion.confidence,
                "dynamic_risk_score": dynamic.score,
                "severity": dynamic.severity,
                "remediation_priority": remediation_priority,
                "sources": list(fusion.corroborated_sources),
            },
        )
        return result

    @staticmethod
    def _shodan_ports(external: dict[str, Any]) -> int:
        total = 0
        for item in external.get("items", []):
            if not isinstance(item, dict) or str(item.get("source", "")).lower() != "shodan":
                continue
            provenance = item.get("provenance")
            if isinstance(provenance, dict) and isinstance(provenance.get("ports"), list):
                total = max(total, len(provenance["ports"]))
        return total

    @staticmethod
    def _remediation_priority(score: float, confidence: float) -> str:
        if score >= 85 and confidence >= 0.75:
            return "urgent"
        if score >= 70:
            return "high"
        if score >= 45:
            return "normal"
        return "monitor"
