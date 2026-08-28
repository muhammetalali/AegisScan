from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class DynamicRiskAssessment:
    score: float
    severity: str
    adjustments: tuple[dict[str, Any], ...]
    rationale: str
    assessed_at: str


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


class DynamicRiskModel:
    """Context-aware risk overlay for a deterministic base risk score."""

    def assess(
        self,
        *,
        base_score: float,
        behavioral_anomaly: float = 0.0,
        newly_exposed_ports: int = 0,
        critical_service_exposure: bool = False,
        validated_exploitation: bool = False,
        business_impact: float = 0.0,
    ) -> DynamicRiskAssessment:
        score = _clamp(float(base_score))
        adjustments: list[dict[str, Any]] = []

        anomaly = _clamp(float(behavioral_anomaly), 0.0, 1.0)
        if anomaly > 0:
            delta = min(15.0, anomaly * 15.0)
            score = _clamp(score + delta)
            adjustments.append({"factor": "behavioral_anomaly", "input": anomaly, "delta": round(delta, 2), "source": "BTE"})

        ports = max(0, int(newly_exposed_ports))
        if ports:
            delta = min(12.0, ports * 3.0)
            score = _clamp(score + delta)
            adjustments.append({"factor": "newly_exposed_ports", "input": ports, "delta": round(delta, 2), "source": "attack_surface_profiler"})

        if critical_service_exposure:
            delta = 8.0
            score = _clamp(score + delta)
            adjustments.append({"factor": "critical_service_exposure", "input": True, "delta": delta, "source": "asset_context"})

        if validated_exploitation:
            delta = 15.0
            score = _clamp(score + delta)
            adjustments.append({"factor": "validated_exploitation", "input": True, "delta": delta, "source": "validation_engine"})

        impact = _clamp(float(business_impact), 0.0, 100.0)
        if impact:
            delta = (impact - 50.0) * 0.10
            score = _clamp(score + delta)
            adjustments.append({"factor": "business_impact", "input": impact, "delta": round(delta, 2), "source": "asset_context"})

        severity = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 40 else "low" if score > 0 else "unknown"
        rationale = (
            "Base risk was retained without contextual adjustments."
            if not adjustments else
            "Base risk was adjusted using explicitly supplied runtime context: "
            + ", ".join(item["factor"] for item in adjustments) + "."
        )
        return DynamicRiskAssessment(
            score=round(score, 2),
            severity=severity,
            adjustments=tuple(adjustments),
            rationale=rationale,
            assessed_at=datetime.now(timezone.utc).isoformat(),
        )
