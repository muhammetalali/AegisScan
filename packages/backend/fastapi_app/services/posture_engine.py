from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SEVERITY_WEIGHT = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0, "informational": 0.0}
WEIGHTS = {"vulnerability_health": 0.35, "control_effectiveness": 0.20, "evidence_quality": 0.15, "coverage": 0.15, "remediation_effectiveness": 0.15}

@dataclass(frozen=True)
class PostureAssessment:
    score: float
    rating: str
    metrics: tuple[dict[str, Any], ...]
    recommendations: tuple[str, ...]
    trend: dict[str, Any]
    evaluated_at: str

class PostureEngine:
    """Evidence-driven posture scoring with explicit coverage of measured dimensions only."""

    def assess(self, *, validations: list[dict[str, Any]], assets_total: int = 0, assets_covered: int | None = None, trend_scores: list[float] | None = None) -> PostureAssessment:
        findings: list[dict[str, Any]] = []
        evidence_items = 0
        controls_passed = 0
        controls_total = 0
        remediated = 0
        for validation in validations:
            results = validation.get("results") if isinstance(validation.get("results"), dict) else {}
            rows = results.get("findings", []) if isinstance(results, dict) else []
            if isinstance(rows, list):
                findings.extend(x for x in rows if isinstance(x, dict))
            evidence = results.get("evidence", []) if isinstance(results, dict) else []
            if isinstance(evidence, list):
                evidence_items += len(evidence)
            controls = results.get("controls", []) if isinstance(results, dict) else []
            if isinstance(controls, list):
                for control in controls:
                    if not isinstance(control, dict):
                        continue
                    controls_total += 1
                    status = str(control.get("status", "")).lower()
                    if status in {"pass", "passed", "compliant"}:
                        controls_passed += 1
                    remediation_status = str(control.get("remediation_status", "")).lower()
                    if remediation_status in {"verified", "remediated", "resolved"}:
                        remediated += 1

        weighted_debt = sum(SEVERITY_WEIGHT.get(str(f.get("severity", "informational")).lower(), 0.0) for f in findings)
        vulnerability_health = max(0.0, min(100.0, 100.0 - weighted_debt))
        metrics: list[dict[str, Any]] = [{"name": "Vulnerability Health", "value": round(vulnerability_health, 2), "max_value": 100, "category": "vulnerabilities", "measured": True}]
        measured: dict[str, float] = {"vulnerability_health": vulnerability_health}

        if controls_total:
            control_effectiveness = 100.0 * controls_passed / controls_total
            measured["control_effectiveness"] = control_effectiveness
            metrics.append({"name": "Control Effectiveness", "value": round(control_effectiveness, 2), "max_value": 100, "category": "controls", "measured": True})
        else:
            metrics.append({"name": "Control Effectiveness", "value": None, "max_value": 100, "category": "controls", "measured": False})

        if validations:
            evidence_quality = min(100.0, evidence_items * 5.0)
            measured["evidence_quality"] = evidence_quality
            metrics.append({"name": "Evidence Quality", "value": round(evidence_quality, 2), "max_value": 100, "category": "evidence", "measured": True})
        else:
            metrics.append({"name": "Evidence Quality", "value": None, "max_value": 100, "category": "evidence", "measured": False})

        if assets_covered is not None and assets_total > 0:
            coverage = max(0.0, min(100.0, 100.0 * assets_covered / assets_total))
            measured["coverage"] = coverage
            metrics.append({"name": "Coverage", "value": round(coverage, 2), "max_value": 100, "category": "coverage", "measured": True})
        else:
            metrics.append({"name": "Coverage", "value": None, "max_value": 100, "category": "coverage", "measured": False})

        if controls_total:
            remediation_effectiveness = 100.0 * remediated / controls_total
            measured["remediation_effectiveness"] = remediation_effectiveness
            metrics.append({"name": "Remediation Effectiveness", "value": round(remediation_effectiveness, 2), "max_value": 100, "category": "remediation", "measured": True})
        else:
            metrics.append({"name": "Remediation Effectiveness", "value": None, "max_value": 100, "category": "remediation", "measured": False})

        total_weight = sum(WEIGHTS[key] for key in measured)
        score = round(sum(value * WEIGHTS[key] for key, value in measured.items()) / total_weight, 2) if measured else 0.0
        history = [max(0.0, min(100.0, float(x))) for x in (trend_scores or [])]
        change = round(history[-1] - history[0], 2) if len(history) >= 2 else 0.0
        direction = "improving" if change > 0.5 else "declining" if change < -0.5 else "stable"
        trend_adjustment = min(5.0, change * 0.25) if change > 0.5 else max(-5.0, change * 0.25) if change < -0.5 else 0.0
        score = round(max(0.0, min(100.0, score + trend_adjustment)), 2)
        rating = "excellent" if score >= 90 else "good" if score >= 75 else "fair" if score >= 60 else "poor" if score > 0 else "unknown"

        recommendations: list[str] = []
        critical = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
        if critical: recommendations.append(f"Prioritize {critical} critical finding(s) for remediation and re-validation.")
        if measured.get("coverage", 100) < 80: recommendations.append("Increase measured asset coverage before relying on the current posture score.")
        if measured.get("control_effectiveness", 100) < 75: recommendations.append("Increase control validation coverage and resolve failed controls.")
        if measured.get("evidence_quality", 100) < 60: recommendations.append("Collect stronger evidence from completed validations and intelligence sources.")
        if measured.get("remediation_effectiveness", 100) < 70: recommendations.append("Close the remediation-to-revalidation loop and verify fixes with security tooling.")
        if direction == "declining": recommendations.append("Posture is declining; investigate recent risk or exposure changes.")
        if not recommendations: recommendations.append("Maintain continuous assurance and monitor measured posture trend.")

        enriched_metrics = tuple({**metric, "trend": direction, "percentage": metric.get("value")} for metric in metrics)
        return PostureAssessment(score=score, rating=rating, metrics=enriched_metrics, recommendations=tuple(recommendations), trend={"direction": direction, "change_rate": change, "samples": len(history)}, evaluated_at=datetime.now(timezone.utc).isoformat())
