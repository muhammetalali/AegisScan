from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FusionResult:
    score: float
    confidence: str
    rationale: str
    contributing_sources: tuple[str, ...]
    evidence: tuple[dict[str, Any], ...]


class FusionEngine:
    """Deterministic, explainable multi-source confidence fusion."""

    weights = {"nvd": 0.25, "osv": 0.20, "cisa_kev": 0.25, "epss": 0.15, "greynoise": 0.10, "exploitdb": 0.05}

    def fuse(self, sources: dict[str, dict[str, Any]]) -> dict[str, Any]:
        score = 0.0
        present: list[str] = []
        evidence: list[dict[str, Any]] = []
        for name, weight in self.weights.items():
            item = sources.get(name) or {}
            if not item or item.get("_error"):
                continue
            signal = self._signal(name, item)
            score += weight * signal
            present.append(name)
            evidence.append({"source": name, "signal": round(signal, 4), "weight": weight})
        score = round(min(1.0, score + min(0.15, max(0, len(present) - 1) * 0.025)), 4)
        confidence = "high" if score >= 0.75 else "medium" if score >= 0.50 else "low"
        missing = sorted(set(self.weights) - set(present))
        rationale = f"Agreement across {', '.join(present) or 'no available sources'} produced {score:.0%} confidence."
        if missing:
            rationale += f" Unavailable sources: {', '.join(missing)}."
        return asdict(FusionResult(score, confidence, rationale, tuple(present), tuple(evidence)))

    @staticmethod
    def _signal(name: str, item: dict[str, Any]) -> float:
        if name == "cisa_kev":
            return 1.0 if item.get("cveID") else 0.0
        if name == "epss":
            try:
                return max(0.0, min(1.0, float(item.get("epss", 0))))
            except (TypeError, ValueError):
                return 0.0
        return 1.0 if item else 0.0
