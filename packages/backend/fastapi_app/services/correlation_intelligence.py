from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CorrelationResult:
    entity_id: str
    confidence: float
    relationships: tuple[dict[str, Any], ...]
    conflicts: tuple[dict[str, Any], ...]


def correlate(entity_id: str, evidence: list[dict[str, Any]]) -> CorrelationResult:
    """Correlate independent evidence without treating source agreement as proof."""
    relationships: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    by_claim: dict[str, list[dict[str, Any]]] = {}
    for item in evidence[:500]:
        claim = str(item.get("claim") or item.get("type") or "unknown").strip().lower()
        by_claim.setdefault(claim, []).append(item)
    weighted = 0.0
    total = 0.0
    for claim, items in by_claim.items():
        sources = {str(x.get("source", "unknown")) for x in items}
        scores = [float(x.get("confidence", 0.5)) for x in items]
        agreement = sum(scores) / len(scores)
        weighted += min(1.0, agreement + min(0.2, (len(sources) - 1) * 0.1))
        total += 1.0
        relationships.append({"claim": claim, "sources": sorted(sources), "agreement": round(agreement, 3)})
        values = {str(x.get("value")) for x in items if x.get("value") is not None}
        if len(values) > 1:
            conflicts.append({"claim": claim, "values": sorted(values), "sources": sorted(sources)})
    confidence = round(min(1.0, weighted / total) if total else 0.0, 3)
    return CorrelationResult(entity_id, confidence, tuple(relationships), tuple(conflicts))
