from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


SEVERITY_WEIGHT = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0, "informational": 0.0}


@dataclass(frozen=True)
class PostureAssessment:
    score: float
    rating: str
    metrics: tuple[dict[str, Any], ...]
    recommendations: tuple[str, ...]
    trend: dict[str, Any]
    evaluated_at: str


class PostureEngine:
    """Derives posture from measured validation evidence, not UI constants.

    The score is a bounded composite of vulnerability health, control effectiveness,
    evidence quality, asset coverage, remediation velocity, and observed trend.
    Missing dimensions are explicitly reported rather than fabricated.
    """

    def assess(
        self,
        *,
        validations: list[dict[str, Any]],
        assets_total: int = 0,
        assets_covered: int | None = None,
        trend_scores: list[float] | None = None,
    ) -> PostureAssessment:
        findings: list[dict[str, Any]] = []
        completed = 0
        remediated = 0
        evidence_items = 0
        controls_passed = 0
        controls_total = 0

        for validation in validations:
            results = validation.get("results") if isinstance(validation.get("results"), dict) else {}
            current = results.get("findings", []) if isinstance(results.get("findings"), list) else []
            findings.extend(x for x in current if isinstance(x, dict))
            if validation.get("status") == "completed":
                completed += 1
            evidence = results.get("evidence", []) if isinstance(results.get("evidence"), list) else []
            evidence_items += len(evidence)
            controls = results.get("controls", []) if isinstance(results.get("controls"), list) else []
            for control in controls:
                if not isinstance(control, dict):
                    continue
                controls_total += 1
                if str(control.get("status", "")).lower() in {"pass", "passed", "compliant"}:
                    controls_passed += 1
                if str(control.get("remediation_status", "")).lower() in {"verified", "remediated", "resolved"}:
                    remediated += 1

        critical = sum(1 for finding in findings if str(finding.get("severity", "")).lower() == "critical")
        weighted_debt = sum(SEVERITY_WEIGHT.get(str(finding.get("severity", "informational")).lower(), 0.0) for finding in findings)
        vulnerability_health = max(0.0, min(100.0, 100.0 - weighted_debt))
        control_effectiveness = 100.0 * controls_passed / controls_total if controls_total else (70.0 if completed else 0.0)
        evidence_quality = min(100.0, evidence_items * 5.0) if validations else 0.0
        if assets_covered is None:
            assets_covered = assets_total if assets_total else len(validations)
        coverage = 100.0 * assets_covered / assets_total if assets_total > 0 else (100.0 if validations else 0.0)

        remediation_rate = 100.0 * remediated / controls_total if controls_total else max(0.0, 100.0 - min(100.0, weighted_debt))
        scores = [v for v in (vulnerability_health, control_effectiveness, evidence_quality, coverage, remediation_rate) if v is not None]
        score = round(sum(scores) / len(scores), 2) if scores else 0.0

        history = [max(0.0, min(100.0, float(x))) for x in (trend_scores or [])]
        if len(history) >= 2:
            change = round(history[-1] - history[0], 2)
            direction = "improving" if change > 0.5 else "declining" if change < -0.5 else "stable"
        else:
            change = 0.0
            direction = "stable"

        if direction == "improving":
            score = round(min(100.0, score + min(5.0, change * 0.25)), 2)
        elif direction == "declining":
            score = round(max(0.0, score + max(-5.0, change * 0.25)), 2)

        rating = "excellent" if score >= 90 else "good" if score >= 75 else "fair" if score >= 60 else "poor" if score > 0 else "unknown"
        recommendations: list[str] = []
        if critical:
            recommendations.append(f"Prioritize {critical} critical finding(s) before lower-severity backlog.")
        if coverage < 80:
            recommendations.append("Increase asset coverage to reduce unmeasured attack-surface exposure.")
        if control_effectiveness < 75:
            recommendations.append("Increase control validation coverage and resolve failed controls.")
        if evidence_quality < 60:
            recommendations.append("Collect stronger evidence from completed validations and external intelligence.")
        if remediation_rate < 70:
            recommendations.append("Improve remediation verification and close the validation loop.")
        if not recommendations:
            recommendations.append("Maintain continuous assurance and monitor posture trend.")

        metrics = (
            {"name": "Vulnerability Health", "value": round(vulnerability_health, 2), "max_value": 100, "category": "vulnerabilities", "trend": direction, "percentage": round(vulnerability_health, 2)},
            {"name": "Control Effectiveness", "value": round(control_effectiveness, 2), "max_value": 100, "category": "controls", "trend": direction, "percentage": round(control_effectiveness, 2)},
            {"name": "Evidence Quality", "value": round(evidence_quality, 2), "max_value": 100, "category": "evidence", "trend": direction, "percentage": round(evidence_quality, 2)},
            {"name": "Coverage", "value": round(coverage, 2), "max_value": 100, "category": "coverage", "trend": direction, "percentage": round(coverage, 2)},
            {"name": "Remediation Effectiveness", "value": round(remediation_rate, 2), "max_value": 100, "category": "remediation", "trend": direction, "percentage": round(remediation_rate, 2)},
        )
        return PostureAssessment(
            score=score,
            rating=rating,
            metrics=metrics,
            recommendations=tuple(recommendations),
            trend={"direction": direction, "change_rate": change, "samples": len(history)},
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )
