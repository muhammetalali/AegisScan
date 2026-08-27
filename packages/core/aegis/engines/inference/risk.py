"""Risk Assessment Engine — محرك تقييم المخاطر.

يجمع بين الخطورة (Severity) ودرجة الثقة (Confidence) لحساب
 SCORE = severity_weight × confidence × 100
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.finding import Finding, Severity

logger = logging.getLogger("aegis.inference.risk")


# أوزان الخطورة (من NIST CVSS)
SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

# حدود SCOR
RISK_THRESHOLDS = {
    "critical": 75,
    "high": 50,
    "medium": 25,
    "low": 10,
    "info": 0,
}


class RiskAssessmentEngine:
    """محرك تقييم المخاطر — يحسب درجة المخاطرة لكل ثغرة."""

    name = "RiskAssessmentEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def assess_finding(
        self,
        finding: Finding,
        confidence: float,
    ) -> Dict[str, Any]:
        """تقييم ثغرة واحدة.

        Returns:
            {
                "finding_id": str,
                "risk_score": float (0-100),
                "risk_level": str,
                "severity": str,
                "confidence": float,
                "components": {...}
            }
        """
        severity = finding.severity
        sev_weight = SEVERITY_WEIGHTS.get(severity, 0.1)

        # حساب النتيجة
        risk_score = sev_weight * confidence * 100
        risk_score = round(min(100.0, max(0.0, risk_score)), 1)

        # تحديد مستوى المخاطرة
        risk_level = self._classify_risk(risk_score)

        result = {
            "finding_id": finding.id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity": severity.value,
            "confidence": confidence,
            "components": {
                "severity_weight": sev_weight,
                "confidence": confidence,
            },
        }

        await self.event_bus.publish(
            topic="risk.assessed",
            payload=result,
            source=self.name,
        )

        logger.info(
            "مخاطرة %s: %.1f (%s) — %s / ثقة %.3f",
            finding.id, risk_score, risk_level,
            severity.value, confidence,
        )
        return result

    async def assess_all(
        self,
        findings: List[Finding],
        confidences: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """تقييم مجموعة ثغرات."""
        results = []
        for finding in findings:
            conf = confidences.get(finding.id, 0.5)
            result = await self.assess_finding(finding, conf)
            results.append(result)

        # ترتيب حسب risk_score تنازلياً
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    @staticmethod
    def _classify_risk(score: float) -> str:
        """تصنيف النتيجة إلى مستوى مخاطرة."""
        if score >= RISK_THRESHOLDS["critical"]:
            return "critical"
        if score >= RISK_THRESHOLDS["high"]:
            return "high"
        if score >= RISK_THRESHOLDS["medium"]:
            return "medium"
        if score >= RISK_THRESHOLDS["low"]:
            return "low"
        return "info"

    def get_risk_summary(
        self, assessed: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """ملخص المخاطرة."""
        summary = {
            "total": len(assessed),
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "average_score": 0.0,
        }
        if not assessed:
            return summary

        total_score = 0.0
        for item in assessed:
            level = item.get("risk_level", "info")
            summary[level] = summary.get(level, 0) + 1
            total_score += item.get("risk_score", 0.0)

        summary["average_score"] = round(total_score / len(assessed), 1)
        return summary
