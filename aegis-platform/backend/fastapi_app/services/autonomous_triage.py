from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


def triage_graph(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = graph.get("nodes", []) or []
    edges = graph.get("edges", []) or []
    degree: dict[str, int] = {str(n.get("id")): 0 for n in nodes}
    for edge in edges:
        degree[str(edge.get("source"))] = degree.get(str(edge.get("source")), 0) + 1
        degree[str(edge.get("target"))] = degree.get(str(edge.get("target")), 0) + 1

    priorities: list[dict[str, Any]] = []
    for node in nodes:
        node_id = str(node.get("id"))
        risk = float(node.get("risk", 0) or 0)
        confidence = float(node.get("confidence", 0) or 0)
        conflicts = float(node.get("conflicts", 0) or 0)
        sources = float(node.get("sources", 0) or 0)
        connectivity = min(100.0, degree.get(node_id, 0) * 12.0)
        evidence_strength = min(100.0, confidence + min(20.0, sources * 4.0))
        conflict_penalty = min(35.0, conflicts * 8.0)
        priority = _clamp(risk * 0.42 + connectivity * 0.18 + evidence_strength * 0.25 + (100 - conflict_penalty) * 0.15)
        if priority >= 85:
            urgency = "critical"
        elif priority >= 70:
            urgency = "high"
        elif priority >= 45:
            urgency = "medium"
        else:
            urgency = "low"
        if conflicts > 0:
            action = "Investigate conflicting source signals and inspect corroborating evidence before closing the decision."
        elif evidence_strength < 55:
            action = "Collect stronger evidence with a focused re-validation before remediation acceptance."
        elif risk >= 80 and degree.get(node_id, 0) >= 3:
            action = "Contain the high-impact path, then launch remediation and immediate re-validation."
        elif risk >= 65:
            action = "Prioritize remediation and schedule a targeted re-validation."
        else:
            action = "Monitor and address during the next assurance cycle."
        priorities.append({
            "nodeId": node_id,
            "label": node.get("label", node_id),
            "kind": node.get("kind", "unknown"),
            "priority": priority,
            "urgency": urgency,
            "risk": _clamp(risk),
            "confidence": _clamp(confidence),
            "conflicts": int(conflicts),
            "connectivity": _clamp(connectivity),
            "evidenceStrength": _clamp(evidence_strength),
            "recommendedAction": action,
            "investigationBrief": f"{node.get('label', node_id)} has priority {priority}/100 with risk {risk}/100 and confidence {confidence}/100.",
            "executiveImpact": "Board-level attention recommended" if priority >= 85 else "Management attention recommended" if priority >= 70 else "Operational follow-up",
        })

    priorities.sort(key=lambda item: item["priority"], reverse=True)
    exposure = _clamp(sum(float(p["risk"]) for p in priorities[:10]) / max(1, min(10, len(priorities)))) if priorities else 0
    executive_priority = _clamp(sum(float(p["priority"]) for p in priorities[:5]) / max(1, min(5, len(priorities)))) if priorities else 0
    conflicted = sum(1 for p in priorities if p["conflicts"] > 0)
    evidence_backed = sum(1 for p in priorities if p["evidenceStrength"] >= 70)

    return {
        "priorities": priorities[:25],
        "topPriority": priorities[0] if priorities else None,
        "metrics": {
            "riskExposure": exposure,
            "executivePriority": executive_priority,
            "conflictedNodes": conflicted,
            "evidenceBackedNodes": evidence_backed,
            "triagedNodes": len(priorities),
        },
    }


def build_triage(intelligence: dict[str, Any]) -> dict[str, Any]:
    """Compatibility adapter for existing decision-pack consumers.

    Graph Intelligence exposes `priorities`; the legacy Decision layer expects
    `items`. Keep one scoring source and translate the shape without duplicating
    triage logic.
    """
    priorities = intelligence.get("priorities") or []
    items: list[dict[str, Any]] = []
    for priority in priorities:
        items.append({
            "nodeId": priority.get("nodeId"),
            "label": priority.get("label"),
            "kind": priority.get("kind"),
            "priority": priority.get("priority", 0),
            "urgency": priority.get("urgency", "low"),
            "risk": priority.get("risk", 0),
            "confidence": priority.get("confidence", 0),
            "conflicts": priority.get("conflicts", 0),
            "evidenceStrength": priority.get("evidenceStrength", 0),
            "recommendedAction": priority.get("recommendedAction"),
            "investigationBrief": priority.get("investigationBrief"),
            "executiveImpact": priority.get("executiveImpact"),
        })
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "items": items,
        "metrics": intelligence.get("metrics", {}),
    }
