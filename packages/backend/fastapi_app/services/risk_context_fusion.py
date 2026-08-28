from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .dynamic_risk_engine import DynamicRiskModel
from .fusion_engine import FusionEngine


@dataclass(frozen=True)
class IntegratedRiskResult:
    fusion: dict[str, Any]
    dynamic: dict[str, Any]
    risk_delta: float
    decision: str
    lineage: tuple[dict[str, Any], ...]


class RiskContextFusion:
    """Integrates external intelligence and remediation validation into one risk decision."""

    def __init__(self) -> None:
        self.fusion_engine = FusionEngine()
        self.dynamic_model = DynamicRiskModel()

    def evaluate(
        self,
        *,
        base_observations: dict[str, dict[str, Any]] | None = None,
        external_intelligence: list[dict[str, Any]] | None = None,
        remediation: dict[str, Any] | None = None,
        behavioral_anomaly: float = 0.0,
        newly_exposed_ports: int = 0,
        critical_service_exposure: bool = False,
        business_impact: float = 0.0,
    ) -> IntegratedRiskResult:
        observations = dict(base_observations or {})
        lineage: list[dict[str, Any]] = []

        for item in external_intelligence or []:
            source = str(item.get("source") or "external").lower()
            confidence = self._score(item)
            observations[source] = {
                "external": True,
                "confidence": confidence,
                "indicator": item.get("indicator"),
                "known_exploited": item.get("known_exploited"),
            }
            lineage.append({"stage": "external_intelligence", "source": source, "confidence": confidence})
            if item.get("known_exploited") is True:
                observations["cisa_kev"] = {"known": True}

        remediation_status = str((remediation or {}).get("status") or "not_evaluated").lower()
        remediation_passed = remediation_status in {"passed", "validated", "fixed"}
        remediation_regression = bool((remediation or {}).get("regression"))
        validation_delta = float((remediation or {}).get("risk_delta") or 0.0)

        if remediation_passed:
            observations["remediation_validation"] = {"passed": True, "risk_delta": validation_delta}
            lineage.append({"stage": "remediation_validation", "status": remediation_status, "risk_delta": validation_delta})
        elif remediation_status not in {"not_evaluated", "skipped"}:
            observations["remediation_validation"] = {"passed": False, "regression": remediation_regression}
            lineage.append({"stage": "remediation_validation", "status": remediation_status, "regression": remediation_regression})

        fusion = self.fusion_engine.fuse(observations)
        validated_exploitation = any(
            item.get("known_exploited") is True or str(item.get("status", "")).lower() == "validated"
            for item in (external_intelligence or [])
        )
        base_score = fusion.score
        if remediation_passed:
            base_score = max(0.0, base_score + min(0.0, validation_delta))
        elif remediation_regression:
            base_score = min(100.0, base_score + max(0.0, abs(validation_delta)))

        dynamic = self.dynamic_model.assess(
            base_score=base_score,
            behavioral_anomaly=behavioral_anomaly,
            newly_exposed_ports=newly_exposed_ports,
            critical_service_exposure=critical_service_exposure,
            validated_exploitation=validated_exploitation,
            business_impact=business_impact,
        )
        lineage.append({"stage": "dynamic_risk", "score": dynamic.score, "severity": dynamic.severity})

        decision = "escalate" if dynamic.severity == "critical" else "review" if dynamic.severity == "high" else "monitor"
        if remediation_passed and dynamic.severity in {"low", "medium"}:
            decision = "accept_remediation"
        if remediation_regression:
            decision = "rollback_or_rework"

        return IntegratedRiskResult(
            fusion={
                "score": fusion.score,
                "confidence": fusion.confidence,
                "rationale": fusion.rationale,
                "corroborated_sources": list(fusion.corroborated_sources),
                "conflicts": list(fusion.conflicts),
                "lineage": list(fusion.lineage),
            },
            dynamic={
                "score": dynamic.score,
                "severity": dynamic.severity,
                "adjustments": list(dynamic.adjustments),
                "rationale": dynamic.rationale,
                "assessed_at": dynamic.assessed_at,
            },
            risk_delta=round(dynamic.score - fusion.score, 2),
            decision=decision,
            lineage=tuple(lineage),
        )

    @staticmethod
    def _score(item: dict[str, Any]) -> float:
        for key in ("confidence", "score", "severity_score"):
            value = item.get(key)
            if value is None:
                continue
            try:
                number = float(value)
                return max(0.0, min(1.0, number / 100.0 if number > 1 else number))
            except (TypeError, ValueError):
                continue
        return 0.5
