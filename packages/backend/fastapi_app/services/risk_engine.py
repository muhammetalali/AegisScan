from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .advanced_intelligence import predictive_signal


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    severity: str
    confidence: float
    factors: tuple[dict[str, object], ...]
    decision_id: str
    lineage: tuple[dict[str, object], ...]
    prediction: dict[str, float]


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def assess_risk(*, cvss: float | None, epss: float | None, kev: bool, matched_assets: int,
                published: str | None, source_count: int, exposure: float | None = None,
                business_impact: float | None = None, history: list[float] | None = None) -> RiskAssessment:
    factors: list[dict[str, object]] = []
    lineage: list[dict[str, object]] = []

    cvss_component = _clamp((cvss or 0.0) / 10.0 * 45.0)
    factors.append({"name": "cvss", "weight": 45, "value": cvss, "contribution": round(cvss_component, 2)})
    lineage.append({"factor": "cvss", "source": "NVD", "value": cvss})

    epss_component = _clamp((epss or 0.0) * 100.0 * 25.0 / 100.0)
    factors.append({"name": "epss", "weight": 25, "value": epss, "contribution": round(epss_component, 2)})
    lineage.append({"factor": "epss", "source": "FIRST EPSS", "value": epss})

    kev_component = 20.0 if kev else 0.0
    factors.append({"name": "known_exploited", "weight": 20, "value": kev, "contribution": kev_component})
    lineage.append({"factor": "known_exploited", "source": "CISA KEV", "value": kev})

    exposure_value = max(0.0, min(1.0, exposure if exposure is not None else (1.0 if matched_assets else 0.0)))
    exposure_component = 10.0 * exposure_value
    factors.append({"name": "asset_exposure", "weight": 10, "value": matched_assets, "contribution": round(exposure_component, 2)})
    lineage.append({"factor": "asset_exposure", "source": "asset-correlation", "value": exposure_value})

    raw = _clamp(cvss_component + epss_component + kev_component + exposure_component)
    if business_impact is not None:
        impact = _clamp(float(business_impact), 0, 100)
        adjustment = (impact - 50.0) * 0.05
        raw = _clamp(raw + adjustment)
        lineage.append({"factor": "business_impact", "source": "asset-context", "value": impact, "adjustment": round(adjustment, 2)})

    if published:
        try:
            published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - published_at).days)
            age_factor = min(5.0, age_days / 365.0)
            raw = _clamp(raw + age_factor)
            factors.append({"name": "age_uncertainty", "weight": 5, "value": age_days, "contribution": round(age_factor, 2)})
            lineage.append({"factor": "age_uncertainty", "source": "published_timestamp", "value": age_days})
        except ValueError:
            pass

    source_confidence = _clamp(source_count / 4.0)
    confidence = _clamp(0.55 + source_confidence * 0.45)
    if matched_assets == 0:
        confidence *= 0.85
    if cvss is None:
        confidence *= 0.8
    confidence = round(confidence, 3)

    prediction = predictive_signal(history or [])
    decision_id = f"risk-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}"
    lineage.append({"factor": "decision", "source": "risk-engine-v2", "decision_id": decision_id})
    severity = "critical" if raw >= 85 else "high" if raw >= 70 else "medium" if raw >= 40 else "low" if raw > 0 else "unknown"
    return RiskAssessment(score=round(raw, 2), severity=severity, confidence=confidence,
                          factors=tuple(factors), decision_id=decision_id,
                          lineage=tuple(lineage), prediction=prediction)
