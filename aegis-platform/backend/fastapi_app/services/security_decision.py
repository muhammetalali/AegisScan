from __future__ import annotations

from typing import Any


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


def build_decision_pack(triage: dict[str, Any]) -> dict[str, Any]:
    items = triage.get("items", [])
    decisions = []
    for index, item in enumerate(items[:20]):
        risk = float(item.get("risk", 0) or 0)
        confidence = float(item.get("confidence", 0) or 0)
        conflicts = int(item.get("conflicts", 0) or 0)
        priority = float(item.get("priority", 0) or 0)
        impact = _clamp(risk * 0.55 + priority * 0.3 + min(15, conflicts * 5))
        urgency = "critical" if priority >= 85 or risk >= 90 else "high" if priority >= 70 or risk >= 75 else "medium" if priority >= 45 else "low"
        node_id = str(item.get("nodeId") or item.get("id") or f"signal-{index}")
        action = item.get("recommendedAction") or ("Investigate and contain" if urgency in {"critical", "high"} else "Review and validate")
        decisions.append({
            "decisionId": f"decision:{node_id}",
            "nodeId": node_id,
            "label": item.get("label", "Security signal"),
            "urgency": urgency,
            "risk": _clamp(risk),
            "confidence": _clamp(confidence),
            "conflicts": conflicts,
            "priority": _clamp(priority),
            "executiveImpact": impact,
            "recommendedAction": action,
            "investigationBrief": item.get("investigationBrief") or "Validate the highest-impact evidence and resolve conflicting signals.",
            "remediationBrief": "Apply the recommended control, verify the affected asset, then re-run validation.",
            "revalidationPlan": ["Confirm scope and evidence", "Apply remediation", "Run targeted re-validation", "Compare before/after risk"],
        })
    decisions.sort(key=lambda x: (x["priority"], x["executiveImpact"]), reverse=True)
    return {
        "generatedAt": triage.get("generatedAt"),
        "decisions": decisions,
        "summary": {
            "total": len(decisions),
            "critical": sum(d["urgency"] == "critical" for d in decisions),
            "high": sum(d["urgency"] == "high" for d in decisions),
            "requiresInvestigation": sum(d["conflicts"] > 0 or d["confidence"] < 70 for d in decisions),
            "executivePriority": _clamp(sum(d["executiveImpact"] for d in decisions[:5]) / max(1, min(5, len(decisions)))),
        },
    }
