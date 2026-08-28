from __future__ import annotations

from typing import Any

from .dynamic_risk_engine import DynamicRiskModel
from .external_intelligence import ExternalIntelligenceFabric
from .fusion_engine import FusionEngine
from .intelligence_fabric import IntelligenceFabric
from .remediation_validation import RemediationValidationSuite


class AssuranceRiskPipeline:
    """Correlate vulnerability, external CTI, remediation and runtime context."""

    def __init__(
        self,
        *,
        intelligence: IntelligenceFabric | None = None,
        external: ExternalIntelligenceFabric | None = None,
        fusion: FusionEngine | None = None,
        dynamic_risk: DynamicRiskModel | None = None,
        remediation: RemediationValidationSuite | None = None,
    ) -> None:
        self.intelligence = intelligence or IntelligenceFabric()
        self.external = external or ExternalIntelligenceFabric()
        self.fusion = fusion or FusionEngine()
        self.dynamic_risk = dynamic_risk or DynamicRiskModel()
        self.remediation = remediation or RemediationValidationSuite()

    async def assess(
        self,
        *,
        indicator: str,
        cve_id: str | None = None,
        assets: list[dict[str, Any]] | None = None,
        behavioral_anomaly: float = 0.0,
        newly_exposed_ports: int = 0,
        critical_service_exposure: bool = False,
        business_impact: float = 0.0,
        validated_exploitation: bool = False,
        remediation_candidate: dict[str, Any] | None = None,
        remediation_tools: list[str] | None = None,
        remediation_timeout: int = 180,
    ) -> dict[str, Any]:
        external = await self.external.search(indicator)
        vulnerability: dict[str, Any] | None = None
        if cve_id:
            vulnerability = await self.intelligence.enrich(cve_id, assets or [])

        remediation_result: dict[str, Any] | None = None
        if remediation_candidate is not None:
            remediation_result = await self.remediation.validate_workspace(
                remediation_candidate,
                tools=remediation_tools,
                timeout=remediation_timeout,
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

        return {
            "indicator": indicator,
            "cve_id": cve_id,
            "vulnerability": vulnerability,
            "external_intelligence": external,
            "remediation_validation": remediation_result,
            "fusion": {
                "score": fusion.score,
                "confidence": fusion.confidence,
                "rationale": fusion.rationale,
                "corroborated_sources": list(fusion.corroborated_sources),
                "conflicts": list(fusion.conflicts),
                "lineage": list(fusion.lineage),
            },
            "dynamic_risk": {
                "score": dynamic.score,
                "severity": dynamic.severity,
                "adjustments": list(dynamic.adjustments),
                "rationale": dynamic.rationale,
                "assessed_at": dynamic.assessed_at,
            },
            "decision": {
                "base_score": fusion.score,
                "final_score": dynamic.score,
                "severity": dynamic.severity,
                "confidence": fusion.confidence,
                "derived_newly_exposed_ports": derived_ports,
                "derived_validated_exploitation": derived_exploitation,
            },
        }

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
