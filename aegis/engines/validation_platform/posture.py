"""Security Posture Engine — محرك قياس الوضع الأمني.

يقيس مستوى الأمن باستمرار ويبين كيف يتطور الوضع الأمني أسبوع بعد أسبوع.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.posture")


class PostureRating(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


@dataclass
class PostureMetric:
    """مقياس أمني."""
    metric_id: str
    name: str
    value: float
    max_value: float = 100.0
    category: str = ""
    description: str = ""
    trend: str = "stable"  # improving, declining, stable

    @property
    def percentage(self) -> float:
        return (self.value / max(self.max_value, 1)) * 100


@dataclass
class PostureSnapshot:
    """لقطة للوضع الأمني."""
    snapshot_id: str
    timestamp: datetime
    overall_score: float
    rating: PostureRating
    metrics: List[PostureMetric]
    findings_summary: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class PostureTrend:
    """اتجاه الوضع الأمني."""
    metric_name: str
    snapshots: List[Dict[str, Any]]
    direction: str = "stable"
    change_rate: float = 0.0


class SecurityPostureEngine:
    """محرك قياس الوضع الأمني — يتبع التطور مع الزمن."""

    name = "SecurityPostureEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._snapshots: List[PostureSnapshot] = []
        self._metrics: Dict[str, PostureMetric] = {}

    async def evaluate(
        self,
        scan_results: Dict[str, Any],
        scan_id: str,
    ) -> PostureSnapshot:
        """تقييم الوضع الأمني الحالي."""
        metrics = self._calculate_metrics(scan_results)
        overall = self._calculate_overall_score(metrics)
        rating = self._score_to_rating(overall)

        recommendations = self._generate_recommendations(metrics, rating)

        snapshot = PostureSnapshot(
            snapshot_id=f"ps_{scan_id}",
            timestamp=datetime.now(timezone.utc),
            overall_score=overall,
            rating=rating,
            metrics=metrics,
            findings_summary=scan_results.get("findings_by_severity", {}),
            recommendations=recommendations,
        )

        self._snapshots.append(snapshot)

        # تحديث الاتجاهات
        self._update_trends(metrics)

        await self.event_bus.publish(
            topic="posture.evaluated",
            payload={
                "snapshot_id": snapshot.snapshot_id,
                "overall_score": overall,
                "rating": rating.value,
            },
            source=self.name,
        )
        return snapshot

    async def get_trend(
        self, metric_name: Optional[str] = None, periods: int = 10
    ) -> PostureTrend:
        """获取 الاتجاه."""
        recent = self._snapshots[-periods:]

        if metric_name:
            values = []
            for snap in recent:
                for m in snap.metrics:
                    if m.name == metric_name:
                        values.append({
                            "timestamp": snap.timestamp.isoformat(),
                            "value": m.value,
                        })
                        break
        else:
            values = [
                {
                    "timestamp": s.timestamp.isoformat(),
                    "value": s.overall_score,
                }
                for s in recent
            ]

        # حساب الاتجاه
        if len(values) >= 2:
            first = values[0]["value"]
            last = values[-1]["value"]
            change = last - first
            if change > 2:
                direction = "improving"
            elif change < -2:
                direction = "declining"
            else:
                direction = "stable"
        else:
            direction = "stable"
            change = 0

        return PostureTrend(
            metric_name=metric_name or "overall",
            snapshots=values,
            direction=direction,
            change_rate=round(change, 2),
        )

    async def compare_periods(
        self, period_a_start: str, period_a_end: str,
        period_b_start: str, period_b_end: str,
    ) -> Dict[str, Any]:
        """مقارنة فترتين."""
        def _filter(start: str, end: str) -> List[PostureSnapshot]:
            return [
                s for s in self._snapshots
                if start <= s.timestamp.isoformat() <= end
            ]

        a = _filter(period_a_start, period_a_end)
        b = _filter(period_b_start, period_b_end)

        avg_a = sum(s.overall_score for s in a) / max(len(a), 1)
        avg_b = sum(s.overall_score for s in b) / max(len(b), 1)

        return {
            "period_a_avg": round(avg_a, 1),
            "period_b_avg": round(avg_b, 1),
            "change": round(avg_b - avg_a, 1),
            "improvement": avg_b > avg_a,
        }

    def get_latest(self) -> Optional[PostureSnapshot]:
        return self._snapshots[-1] if self._snapshots else None

    def get_history(self) -> List[PostureSnapshot]:
        return list(self._snapshots)

    def summary(self) -> Dict[str, Any]:
        latest = self.get_latest()
        return {
            "total_snapshots": len(self._snapshots),
            "latest_score": latest.overall_score if latest else 0,
            "latest_rating": latest.rating.value if latest else "unknown",
        }

    def _calculate_metrics(self, results: Dict[str, Any]) -> List[PostureMetric]:
        """حساب المعايير."""
        metrics = []

        # ثغرات
        vulns = results.get("findings_by_severity", {})
        critical = vulns.get("critical", 0)
        high = vulns.get("high", 0)
        medium = vulns.get("medium", 0)

        vuln_score = max(100 - critical * 25 - high * 10 - medium * 3, 0)
        metrics.append(PostureMetric(
            metric_id="vuln_health",
            name="صحة الثغرات",
            value=vuln_score,
            category="vulnerabilities",
        ))

        # التغطية
        controls = results.get("controls_tested", 0)
        effective = results.get("controls_effective", 0)
        coverage = (effective / max(controls, 1)) * 100
        metrics.append(PostureMetric(
            metric_id="control_effectiveness",
            name="فعالية الضوابط",
            value=coverage,
            category="controls",
        ))

        # الثقة
        avg_conf = results.get("avg_confidence", 0.5) * 100
        metrics.append(PostureMetric(
            metric_id="evidence_quality",
            name="جودة الأدلة",
            value=avg_conf,
            category="evidence",
        ))

        # التغطية
        coverage_pct = results.get("coverage_pct", 70)
        metrics.append(PostureMetric(
            metric_id="coverage",
            name="تغطية الكشف",
            value=coverage_pct,
            category="coverage",
        ))

        return metrics

    def _calculate_overall_score(self, metrics: List[PostureMetric]) -> float:
        """حساب النتيجة الإجمالية."""
        if not metrics:
            return 50.0
        weights = {
            "vuln_health": 0.35,
            "control_effectiveness": 0.30,
            "evidence_quality": 0.20,
            "coverage": 0.15,
        }
        total = 0.0
        for m in metrics:
            w = weights.get(m.metric_id, 0.1)
            total += m.percentage * w
        return round(total, 1)

    def _score_to_rating(self, score: float) -> PostureRating:
        if score >= 85:
            return PostureRating.EXCELLENT
        if score >= 70:
            return PostureRating.GOOD
        if score >= 50:
            return PostureRating.FAIR
        if score >= 30:
            return PostureRating.POOR
        return PostureRating.CRITICAL

    def _update_trends(self, metrics: List[PostureMetric]) -> None:
        """تحديث الاتجاهات."""
        if len(self._snapshots) < 2:
            return
        prev = self._snapshots[-2]
        for m in metrics:
            for pm in prev.metrics:
                if pm.name == m.name:
                    diff = m.value - pm.value
                    if diff > 2:
                        m.trend = "improving"
                    elif diff < -2:
                        m.trend = "declining"
                    break

    def _generate_recommendations(
        self, metrics: List[PostureMetric], rating: PostureRating
    ) -> List[str]:
        recs = []
        for m in metrics:
            if m.percentage < 50:
                recs.append(f"تحسين {m.name} ({m.percentage:.0f}%)")
        if rating in (PostureRating.POOR, PostureRating.CRITICAL):
            recs.append("تحسين شامل مطلوب — الوضع الأمني ضعيف")
        if not recs:
            recs.append("الوضع الأمني مقبول — استمرار المراقبة")
        return recs
