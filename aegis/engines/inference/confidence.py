"""Confidence Scoring Engine — محرك درجة الثقة.

الصيغة:
  base=0.45
  + behavioral=0.15
  + structural=0.15
  + extra_sources(max 0.15)
  + historical=0.05
  - conflicts(0.15 each)
= total (0-1)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory
from aegis.models.finding import Finding, Severity

logger = logging.getLogger("aegis.inference.confidence")


class ConfidenceScoringEngine:
    """محرك درجة الثقة — يحسب درجة الثقة لكل ثغرة بناءً على الأدلة."""

    name = "ConfidenceScoringEngine"

    # أوزان المكوّنات
    BASE = 0.45
    BEHAVIORAL_WEIGHT = 0.15
    STRUCTURAL_WEIGHT = 0.15
    EXTRA_SOURCES_WEIGHT = 0.15  # max
    HISTORICAL_WEIGHT = 0.05
    CONFLICT_PENALTY = 0.15

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def score_finding(
        self,
        finding: Finding,
        evidences: List[Evidence],
        historical_stats: Optional[Dict[str, Any]] = None,
    ) -> float:
        """حساب درجة ثقة ثغرة معينة.

        Args:
            finding: الثغرة المراد تقييمها
            evidences: الأدلة الداعمة
            historical_stats: إحصائيات تاريخية (اختياري)

        Returns:
            درجة الثقة النهائية (0-1)
        """
        score = self.BASE

        # 1. السلوكية: هل يوجد أنماط سلوكية مشبوهة؟
        behavioral = self._behavioral_score(evidences)
        score += behavioral

        # 2. الهيكلية: هل تدعم ثغرات أخرى نفس الفئة؟
        structural = self._structural_score(finding, evidences)
        score += structural

        # 3. مصادر إضافية: عدد المصادر المستقلة
        extra = self._extra_sources_score(evidences)
        score += extra

        # 4. تاريخي: هل سبق اكتشاف ثغرات مشابهة؟
        historical = self._historical_score(historical_stats)
        score += historical

        # 5. تعارضات: هل يوجد أدلة متعارضة؟
        conflicts = self._conflict_penalty(evidences)
        score -= conflicts

        final = max(0.0, min(1.0, round(score, 3)))

        # نشر النتيجة
        await self.event_bus.publish(
            topic="confidence.scored",
            payload={
                "finding_id": finding.id,
                "confidence": final,
                "components": {
                    "base": self.BASE,
                    "behavioral": behavioral,
                    "structural": structural,
                    "extra_sources": extra,
                    "historical": historical,
                    "conflicts": -conflicts,
                },
            },
            source=self.name,
        )

        logger.info(
            "ثقة %s: %.3f (behavioral=%.2f, structural=%.2f, extra=%.2f, historical=%.2f, conflicts=%.2f)",
            finding.id, final, behavioral, structural, extra, historical, -conflicts,
        )
        return final

    def _behavioral_score(self, evidences: List[Evidence]) -> float:
        """النتيجة السلوكية: هل توجد أدلة سلوكية (BTE)؟"""
        behavioral = [e for e in evidences if e.evidence_type.value == "behavioral"]
        if not behavioral:
            return 0.0
        avg_conf = sum(e.confidence_weight for e in behavioral) / len(behavioral)
        return min(avg_conf * self.BEHAVIORAL_WEIGHT, self.BEHAVIORAL_WEIGHT)

    def _structural_score(
        self, finding: Finding, evidences: List[Evidence]
    ) -> float:
        """النتيجة الهيكلية: عدد الأدلة التي تدعم نفس الفئة."""
        same_cat = [
            e for e in evidences
            if not hasattr(finding, 'category') or e.category == finding.category
        ]
        if len(same_cat) < 2:
            return 0.0
        return min(
            (len(same_cat) - 1) * 0.05,
            self.STRUCTURAL_WEIGHT,
        )

    def _extra_sources_score(self, evidences: List[Evidence]) -> float:
        """نتيجة المصادر الإضافية: عدد المصادر المستقلة."""
        sources = set(e.source_tool for e in evidences)
        if len(sources) <= 1:
            return 0.0
        extra_count = len(sources) - 1
        return min(extra_count * 0.05, self.EXTRA_SOURCES_WEIGHT)

    def _historical_score(
        self, historical_stats: Optional[Dict[str, Any]]
    ) -> float:
        """النتيجة التاريخية: هل تكررت ثغرات مشابهة سابقاً؟"""
        if not historical_stats:
            return 0.0
        similar_count = historical_stats.get("similar_findings_count", 0)
        if similar_count == 0:
            return 0.0
        return min(similar_count * 0.01, self.HISTORICAL_WEIGHT)

    def _conflict_penalty(self, evidences: List[Evidence]) -> float:
        """خصم التعارض: هل يوجد أدلة بتصنيفات متعارضة؟"""
        categories = [e.category for e in evidences]
        # تعارض: ثغرة在同一 category + في category معاكس
        conflict_pairs = {
            (EvidenceCategory.AUTHENTICATION, EvidenceCategory.AUTHORIZATION),
            (EvidenceCategory.CRYPTOGRAPHY, EvidenceCategory.SECRETS),
        }
        penalty = 0.0
        for cat in categories:
            for pair in conflict_pairs:
                if cat in pair:
                    other = pair[1] if cat == pair[0] else pair[0]
                    if other in categories:
                        penalty += self.CONFLICT_PENALTY
                        break
        return min(penalty, 0.45)  # لا يتجاوز the base
