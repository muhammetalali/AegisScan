from __future__ import annotations

from typing import Any


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


def _correlation_urgency(priority: str | None) -> str | None:
    mapping = {
        "P0-CRITICAL": "critical",
        "P1-HIGH": "high",
        "P2-MEDIUM": "medium",
        "P3-LOW": "low",
    }
    return mapping.get(str(priority)) if priority else None


def build_decision_pack(triage: dict[str, Any]) -> dict[str, Any]:
    items = triage.get("items", [])
    decisions = []
    for index, item in enumerate(items[:20]):
        triage_risk = float(item.get("risk", 0) or 0)
        triage_priority = float(item.get("priority", 0) or 0)
        confidence = float(item.get("confidence", 0) or 0)
        conflicts = int(item.get("conflicts", 0) or 0)

        risk_correlation_id = item.get("riskCorrelationId")
        risk_correlation_sha256 = item.get("riskCorrelationSha256")
        risk_analysis_version = item.get("riskAnalysisVersion")
        risk_correlation_priority = item.get("riskCorrelationPriority")
        risk_correlation_score = item.get("riskCorrelationScore")
        supporting_evidence_count = int(item.get("supportingEvidenceCount", 0) or 0)
        contradicting_evidence_count = int(item.get("contradictingEvidenceCount", 0) or 0)
        neutral_evidence_count = int(item.get("neutralEvidenceCount", 0) or 0)

        correlated = bool(risk_correlation_id and risk_correlation_sha256)
        risk = float(risk_correlation_score) if correlated and risk_correlation_score is not None else triage_risk
        priority = risk if correlated else triage_priority
        urgency = _correlation_urgency(risk_correlation_priority)
        if urgency is None:
            urgency = (
                "critical" if priority >= 85 or risk >= 90
                else "high" if priority >= 70 or risk >= 75
                else "medium" if priority >= 45
                else "low"
            )

        impact = _clamp(risk * 0.55 + triage_priority * 0.3 + min(15, conflicts * 5))
        node_id = str(item.get("nodeId") or item.get("id") or f"signal-{index}")
        decision_id = (
            f"decision:{node_id}:{risk_correlation_id}"
            if correlated else f"decision:{node_id}"
        )

        has_scope = bool(item.get("validationId") and item.get("projectId"))
        contradiction_blocked = correlated and contradicting_evidence_count > 0
        actionable = has_scope and not contradiction_blocked
        if not has_scope:
            actionability_reason = "Context-only graph node; no verified validation/project lineage."
        elif contradiction_blocked:
            actionability_reason = (
                "Contradicting validation evidence is present; investigate and establish a new "
                "supporting correlation snapshot before remediation execution."
            )
        else:
            actionability_reason = None

        if contradiction_blocked:
            action = (
                "Investigate contradictory validation evidence and re-correlate before remediation execution."
            )
        else:
            action = item.get("recommendedAction") or (
                "Investigate and contain" if urgency in {"critical", "high"} else "Review and validate"
            )

        decisions.append({
            "decisionId": decision_id,
            "nodeId": node_id,
            "label": item.get("label", "Security signal"),
            "urgency": urgency,
            "risk": _clamp(risk),
            "confidence": _clamp(confidence),
            "conflicts": conflicts,
            "priority": _clamp(priority),
            "triagePriority": _clamp(triage_priority),
            "executiveImpact": impact,
            "recommendedAction": action,
            "investigationBrief": item.get("investigationBrief") or "Validate the highest-impact evidence and resolve conflicting signals.",
            "remediationBrief": "Apply the recommended control, verify the affected asset, then re-run validation.",
            "revalidationPlan": ["Confirm scope and evidence", "Apply remediation", "Run targeted re-validation", "Compare before/after risk"],
            "validationId": item.get("validationId"),
            "projectId": item.get("projectId"),
            "riskCorrelationId": risk_correlation_id,
            "riskCorrelationSha256": risk_correlation_sha256,
            "riskAnalysisVersion": risk_analysis_version,
            "riskCorrelationPriority": risk_correlation_priority,
            "riskCorrelationScore": float(risk_correlation_score) if risk_correlation_score is not None else None,
            "supportingEvidenceCount": supporting_evidence_count,
            "contradictingEvidenceCount": contradicting_evidence_count,
            "neutralEvidenceCount": neutral_evidence_count,
            "decisionSource": "risk_correlation" if correlated else "assurance_graph",
            "actionable": actionable,
            "actionabilityReason": actionability_reason,
        })

    decisions.sort(key=lambda x: (x["priority"], x["executiveImpact"]), reverse=True)
    return {
        "generatedAt": triage.get("generatedAt"),
        "decisions": decisions,
        "summary": {
            "total": len(decisions),
            "critical": sum(d["urgency"] == "critical" for d in decisions),
            "high": sum(d["urgency"] == "high" for d in decisions),
            "requiresInvestigation": sum(
                d["contradictingEvidenceCount"] > 0 or d["conflicts"] > 0 or d["confidence"] < 70
                for d in decisions
            ),
            "executivePriority": _clamp(
                sum(d["executiveImpact"] for d in decisions[:5]) / max(1, min(5, len(decisions)))
            ),
            "actionable": sum(bool(d["actionable"]) for d in decisions),
            "correlated": sum(bool(d["riskCorrelationId"]) for d in decisions),
        },
    }
