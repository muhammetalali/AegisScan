from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FusionResult:
    score: float
    confidence: float
    rationale: str
    corroborated_sources: tuple[str, ...]
    conflicts: tuple[dict[str, Any], ...]
    lineage: tuple[dict[str, Any], ...]


class FusionEngine:
    """Deterministic, explainable fusion of heterogeneous security evidence.

    Confidence measures evidence agreement/quality; it is never an authorization
    signal and never implies exploitability.
    """

    def fuse(self, observations: dict[str, dict[str, Any]]) -> FusionResult:
        available = {name: value for name, value in observations.items() if value and "_error" not in value}
        sources = tuple(sorted(available))
        scores: list[float] = []
        lineage: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []

        nvd = available.get("nvd", {})
        cvss = self._number(self._nested(nvd, "metrics", "cvssMetricV40", 0, "cvssData", "baseScore"))
        if cvss is None:
            cvss = self._number(self._nested(nvd, "metrics", "cvssMetricV31", 0, "cvssData", "baseScore"))
        if cvss is not None:
            scores.append(cvss / 10.0)
            lineage.append({"source": "nvd", "factor": "cvss", "value": cvss})

        osv = available.get("osv", {})
        osv_score = self._number(self._nested(osv, "severity", 0, "score"))
        if osv_score is not None:
            scores.append(max(0.0, min(1.0, osv_score / 10.0)))
            lineage.append({"source": "osv", "factor": "severity_score", "value": osv_score})

        epss = self._number(available.get("epss", {}).get("epss"))
        if epss is not None:
            scores.append(max(0.0, min(1.0, epss)))
            lineage.append({"source": "epss", "factor": "exploit_probability", "value": epss})

        kev = bool(available.get("cisa_kev"))
        if kev:
            scores.append(1.0)
            lineage.append({"source": "cisa_kev", "factor": "known_exploited", "value": True})

        if len(scores) == 1:
            confidence = 0.55
        elif len(scores) == 2:
            confidence = 0.70
        elif len(scores) >= 3:
            confidence = 0.82
        else:
            confidence = 0.0

        if cvss is not None and epss is not None:
            if cvss >= 7 and epss < 0.01:
                conflicts.append({"type": "severity_vs_exploit_probability", "cvss": cvss, "epss": epss})
                confidence -= 0.08
            elif cvss < 4 and epss >= 0.5:
                conflicts.append({"type": "severity_vs_exploit_probability", "cvss": cvss, "epss": epss})
                confidence -= 0.05

        confidence = round(max(0.0, min(1.0, confidence)), 3)
        score = round((sum(scores) / len(scores)) * 100.0, 2) if scores else 0.0
        if kev:
            score = round(max(score, 85.0), 2)
        score = round(max(0.0, min(100.0, score)), 2)

        if not sources:
            rationale = "No provider produced usable evidence; confidence is 0%."
        else:
            joined = ", ".join(s.upper() for s in sources)
            rationale = f"Evidence from {joined} fused into {confidence * 100:.0f}% confidence."
            if conflicts:
                rationale += " Conflicting severity/exploitability signals were retained for investigation."
            if kev:
                rationale += " CISA KEV confirms known exploitation."

        return FusionResult(score=score, confidence=confidence, rationale=rationale,
                            corroborated_sources=sources, conflicts=tuple(conflicts),
                            lineage=tuple(lineage))

    @staticmethod
    def _number(value: Any) -> float | None:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _nested(value: Any, *path: Any) -> Any:
        current = value
        try:
            for part in path:
                current = current[part]
            return current
        except (KeyError, IndexError, TypeError):
            return None
