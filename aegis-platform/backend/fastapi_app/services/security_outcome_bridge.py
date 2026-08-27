from __future__ import annotations

from typing import Any


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


def build_security_outcome(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes", []) or []
    intelligence = graph.get("intelligence", {}) or {}
    findings = [n for n in nodes if n.get("kind") == "finding"]
    evidence = [n for n in nodes if n.get("kind") == "evidence"]
    conflicts = [n for n in nodes if n.get("kind") == "conflict"]
    assets = [n for n in nodes if n.get("kind") == "asset"]

    critical = sum(1 for n in findings if n.get("severity") == "critical")
    high = sum(1 for n in findings if n.get("severity") == "high")
    avg_confidence = _clamp(sum(float(n.get("confidence", 0) or 0) for n in findings) / max(1, len(findings)))
    evidence_coverage = _clamp(100 * len(evidence) / max(1, len(findings))) if findings else (_clamp(100) if evidence else 0)
    conflict_penalty = min(30, len(conflicts) * 6)
    risk_exposure = _clamp(intelligence.get("riskExposure", 0))
    assurance = _clamp(avg_confidence * 0.55 + evidence_coverage * 0.30 + (100 - conflict_penalty) * 0.15)
    posture_score = _clamp(100 - risk_exposure * 0.65 + assurance * 0.35)
    executive_outcome = _clamp(posture_score * 0.5 + assurance * 0.3 + max(0, 100 - high * 8 - critical * 18) * 0.2)

    return {
        "posture": {
            "score": posture_score,
            "riskExposure": risk_exposure,
            "assurance": assurance,
            "criticalFindings": critical,
            "highFindings": high,
            "conflicts": len(conflicts),
            "assets": len(assets),
            "evidence": len(evidence),
        },
        "executive": {
            "outcomeScore": executive_outcome,
            "attention": "critical" if critical else "elevated" if high or conflicts else "normal",
            "evidenceCoverage": evidence_coverage,
            "confidence": avg_confidence,
            "riskExposure": risk_exposure,
            "businessSignal": "exposure_reduced" if risk_exposure < 40 and assurance >= 80 else "review_required",
        },
    }
