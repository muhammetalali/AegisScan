from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    severity: str
    confidence: float
    factors: tuple[dict[str, object], ...]


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def assess_risk(*, cvss: float | None, epss: float | None, kev: bool, matched_assets: int, published: str | None, source_count: int) -> RiskAssessment:
    factors: list[dict[str, object]] = []
    cvss_component = _clamp((cvss or 0.0) / 10.0 * 45.0)
    factors.append({"name": "cvss", "weight": 45, "value": cvss, "contribution": round(cvss_component, 2)})
    epss_component = _clamp((epss or 0.0) * 100.0 * 0.25)
    factors.append({"name": "epss", "weight": 25, "value": epss, "contribution": round(epss_component, 2)})
    kev_component = 20.0 if kev else 0.0
    factors.append({"name": "known_exploited", "weight": 20, "value": kev, "contribution": kev_component})
    exposure_component = 10.0 if matched_assets > 0 else 0.0
    factors.append({"name": "asset_exposure", "weight": 10, "value": matched_assets, "contribution": exposure_component})

    raw = _clamp(cvss_component + epss_component + kev_component + exposure_component)
    age_factor = 0.0
    if published:
        try:
            published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - published_at).days)
            # Old vulnerabilities do not automatically become safer; this is a
            # bounded uncertainty adjustment, never a downward risk discount.
            age_factor = min(5.0, age_days / 365.0)
            raw = _clamp(raw + age_factor)
            factors.append({"name": "age_uncertainty", "weight": 5, "value": age_days, "contribution": round(age_factor, 2)})
        except ValueError:
            pass

    source_confidence = _clamp(source_count / 4.0, 0.0, 1.0)
    confidence = _clamp((0.55 + source_confidence * 0.45) * 100.0) / 100.0
    if matched_assets == 0:
        confidence *= 0.85
    if cvss is None:
        confidence *= 0.8
    confidence = round(confidence, 3)

    severity = "critical" if raw >= 85 else "high" if raw >= 70 else "medium" if raw >= 40 else "low" if raw > 0 else "unknown"
    return RiskAssessment(score=round(raw, 2), severity=severity, confidence=confidence, factors=tuple(factors))
