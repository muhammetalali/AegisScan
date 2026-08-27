from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

SOURCE_TRUST: dict[str, float] = {
    "recon": 0.72,
    "evidence_collection": 0.92,
    "vuln_intelligence": 0.86,
    "validation": 0.94,
    "control_validation": 0.9,
    "coverage_gap": 0.84,
    "attack_path": 0.91,
    "evidence_graph": 0.95,
    "knowledge": 0.72,
    "posture": 0.82,
    "policy_compliance": 0.9,
    "twin_engine": 0.78,
    "scenarios": 0.8,
    "dashboard": 0.62,
    "reporting": 0.68,
}


def _confidence_percent(confidence: float) -> int:
    return max(0, min(100, round(confidence * 100)))


def _engine_signal(engine: str, state: dict[str, Any], validation_id: str) -> dict[str, Any]:
    findings = int(state.get("findings", 0) or 0)
    status = str(state.get("status", "pending"))
    value = "exposure_detected" if findings > 0 else "no_exposure_detected"
    confidence = SOURCE_TRUST.get(engine, 0.7)
    if status not in {"completed", "running"}:
        confidence *= 0.6
    return {
        "id": f"{validation_id}:{engine}",
        "source": engine,
        "claim": "exposure_state",
        "value": value,
        "confidence": _confidence_percent(confidence),
        "weight": round(confidence, 3),
        "observedAt": datetime.utcnow().isoformat(),
        "evidenceId": f"validation:{validation_id}:engine:{engine}",
    }


def correlate_validation(validation_id: str, validation: dict[str, Any]) -> dict[str, Any]:
    signals = [_engine_signal(engine, validation.get("engines_state", {}).get(engine, {}), validation_id) for engine in validation.get("engines", [])]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for signal in signals:
        groups["exposure_state"].append(signal)

    conflicts: list[dict[str, Any]] = []
    total_weight = sum(float(s["weight"]) for s in signals) or 1.0
    weighted_confidence = sum(float(s["confidence"]) * float(s["weight"]) for s in signals) / total_weight if signals else 0.0

    for claim, claim_signals in groups.items():
        values = Counter(s["value"] for s in claim_signals)
        if len(values) <= 1:
            continue
        agreement = max(values.values()) / max(1, len(claim_signals))
        disagreement = 1.0 - agreement
        conflict_impact = round(min(100.0, disagreement * 100.0 * (0.65 + min(len(claim_signals), 6) * 0.05)), 1)
        assurance_after = max(0.0, weighted_confidence - conflict_impact * 0.35)
        conflicts.append({
            "id": f"{validation_id}:{claim}",
            "entityId": validation_id,
            "entityLabel": f"Validation {validation_id}",
            "signals": claim_signals,
            "agreement": round(agreement * 100),
            "recommendedAction": "Run a focused re-validation and inspect evidence from the disagreeing engines before accepting the security decision.",
            "impact": conflict_impact,
            "confidenceBefore": round(weighted_confidence),
            "confidenceAfter": round(assurance_after),
        })

    source_count = len({s["source"] for s in signals})
    return {
        "validationId": validation_id,
        "signals": signals,
        "conflicts": conflicts,
        "conflictCount": len(conflicts),
        "sourceCount": source_count,
        "signalCount": len(signals),
        "weightedConfidence": round(weighted_confidence),
        "agreement": round((1 - sum(c["impact"] for c in conflicts) / max(1, len(conflicts)) / 100) * 100) if conflicts else 100,
    }


def correlate_all(validations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    records = [correlate_validation(vid, item) for vid, item in validations.items()]
    conflicts = [conflict for record in records for conflict in record["conflicts"]]
    signals = [signal for record in records for signal in record["signals"]]
    total_weight = sum(float(s["weight"]) for s in signals) or 1.0
    confidence = round(sum(float(s["confidence"]) * float(s["weight"]) for s in signals) / total_weight) if signals else 0
    agreement = round(sum(r["agreement"] for r in records) / len(records)) if records else 100
    return {
        "items": conflicts,
        "summary": {
            "conflicts": len(conflicts),
            "signals": len(signals),
            "sources": len({s["source"] for s in signals}),
            "agreement": agreement,
            "confidence": confidence,
        },
    }
