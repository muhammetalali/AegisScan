"""Coverage Gap Analyzer — محلل فجوات التغطية.

يحلل فجوات الكشف ويحدد Areas التي لا تغطيها الضوابط.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.coverage_gap")


class GapSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GapCategory(str, Enum):
    DETECTION = "detection"           # فجوة في الكشف
    PREVENTION = "prevention"         # فجوة في الوقاية
    RESPONSE = "response"             # فجوة في الاستجابة
    VISIBILITY = "visibility"         # فجوة في الرؤية
    COVERAGE = "coverage"             # فجوة في التغطية
    INTEGRATION = "integration"       # فجوة في التكامل


@dataclass
class CoverageGap:
    """فجوة تغطية."""
    gap_id: str
    title: str
    description: str
    category: GapCategory
    severity: GapSeverity
    affected_assets: List[str] = field(default_factory=list)
    affected_controls: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    recommendation: str = ""
    effort_estimate: str = ""
    priority_score: float = 0.0
    discovered_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CoverageReport:
    """تقرير التغطية."""
    total_assets: int = 0
    covered_assets: int = 0
    coverage_percentage: float = 0.0
    gaps: List[CoverageGap] = field(default_factory=list)
    gaps_by_category: Dict[str, int] = field(default_factory=dict)
    gaps_by_severity: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class CoverageGapAnalyzer:
    """محرك تحليل فجوات التغطية — يحدد Areas الضعيفة."""

    name = "CoverageGapAnalyzer"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._gaps: Dict[str, CoverageGap] = {}
        self._coverage_map: Dict[str, List[str]] = {}  # asset -> [controls]

    async def analyze(
        self,
        assets: List[Dict[str, Any]],
        controls: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        scan_id: str,
    ) -> CoverageReport:
        """تحليل شامل لفجوات التغطية."""
        self._gaps.clear()
        self._coverage_map.clear()

        # بناء خريطة التغطية
        for asset in assets:
            asset_id = asset.get("asset_id", "")
            self._coverage_map[asset_id] = []

        for control in controls:
            control_id = control.get("control_id", "")
            protected_assets = control.get("protected_assets", [])
            for asset_id in protected_assets:
                self._coverage_map.setdefault(asset_id, []).append(control_id)

        # كشف الفجوات
        await self._detect_detection_gaps(findings)
        await self._detect_prevention_gaps(assets, controls)
        await self._detect_visibility_gaps(assets, controls)
        await self._detect_coverage_gaps(assets, controls)

        # حساب النتائج
        total_assets = len(assets)
        covered = sum(
            1 for a, c in self._coverage_map.items() if c
        )
        coverage_pct = (covered / max(total_assets, 1)) * 100

        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for gap in self._gaps.values():
            by_cat[gap.category.value] = by_cat.get(gap.category.value, 0) + 1
            by_sev[gap.severity.value] = by_sev.get(gap.severity.value, 0) + 1

        report = CoverageReport(
            total_assets=total_assets,
            covered_assets=covered,
            coverage_percentage=round(coverage_pct, 1),
            gaps=list(self._gaps.values()),
            gaps_by_category=by_cat,
            gaps_by_severity=by_sev,
            recommendations=self._generate_recommendations(),
        )

        await self.event_bus.publish(
            topic="coverage_gaps.analyzed",
            payload={
                "total_gaps": len(self._gaps),
                "coverage_pct": coverage_pct,
            },
            source=self.name,
        )

        return report

    async def _detect_detection_gaps(
        self, findings: List[Dict[str, Any]]
    ) -> None:
        """كشف فجوات الكشف."""
        high_findings = [
            f for f in findings
            if f.get("severity") in ("critical", "high")
        ]

        for i, finding in enumerate(high_findings):
            gap = CoverageGap(
                gap_id=f"gap_det_{i}",
                title=f"نتيجة حرجة غير مكتشفة: {finding.get('title', '')}",
                description="توجد ثغرات حرجة لم تكتشفها الضوابط الحالية",
                category=GapCategory.DETECTION,
                severity=GapSeverity.HIGH,
                affected_assets=finding.get("affected_assets", []),
                attack_vectors=[finding.get("title", "")],
                recommendation="تحسين قواعد الكشف وإضافة مراقبة إضافية",
                discovered_at=datetime.now(timezone.utc),
            )
            self._gaps[gap.gap_id] = gap

    async def _detect_prevention_gaps(
        self, assets: List[Dict[str, Any]], controls: List[Dict[str, Any]]
    ) -> None:
        """كشف فجوات الوقاية."""
        unprotected = [
            a for a in assets
            if not self._coverage_map.get(a.get("asset_id", ""), [])
        ]

        if unprotected:
            gap = CoverageGap(
                gap_id="gap_prev_1",
                title=f"{len(unprotected)} أصول بدون ضوابط وقائية",
                description="أصول لم تُحمَّ بأي ضابط أمني",
                category=GapCategory.PREVENTION,
                severity=GapSeverity.CRITICAL,
                affected_assets=[a.get("asset_id", "") for a in unprotected],
                recommendation="نشر ضوابط حماية على الأصول غير المحمية",
                discovered_at=datetime.now(timezone.utc),
            )
            self._gaps[gap.gap_id] = gap

    async def _detect_visibility_gaps(
        self, assets: List[Dict[str, Any]], controls: List[Dict[str, Any]]
    ) -> None:
        """كشف فجوات الرؤية."""
        control_types = {c.get("control_type", "") for c in controls}
        missing_types = {"siem", "ids_ips", "edr"} - control_types

        if missing_types:
            gap = CoverageGap(
                gap_id="gap_vis_1",
                title=f"أدوات مراقبة مفقودة: {', '.join(missing_types)}",
                description="لا توجد أدوات مراقبة كافية",
                category=GapCategory.VISIBILITY,
                severity=GapSeverity.HIGH,
                affected_controls=list(missing_types),
                recommendation=f"نشر: {', '.join(missing_types)}",
                discovered_at=datetime.now(timezone.utc),
            )
            self._gaps[gap.gap_id] = gap

    async def _detect_coverage_gaps(
        self, assets: List[Dict[str, Any]], controls: List[Dict[str, Any]]
    ) -> None:
        """كشف فجوات التغطية العامة."""
        critical_assets = [
            a for a in assets
            if a.get("criticality") in ("critical", "high")
        ]

        for asset in critical_assets:
            asset_id = asset.get("asset_id", "")
            asset_controls = self._coverage_map.get(asset_id, [])
            if len(asset_controls) < 2:
                gap = CoverageGap(
                    gap_id=f"gap_cov_{asset_id}",
                    title=f"ال Asset Critical '{asset_id}' أقل من ضابطين",
                    description="الأصول الحرجة تحتاج تغطية متعددة",
                    category=GapCategory.COVERAGE,
                    severity=GapSeverity.HIGH,
                    affected_assets=[asset_id],
                    affected_controls=asset_controls,
                    recommendation="إضافة ضابط إضافي على الأصول الحرجة",
                    discovered_at=datetime.now(timezone.utc),
                )
                self._gaps[gap.gap_id] = gap

    def _generate_recommendations(self) -> List[str]:
        """توليد توصيات عامة."""
        recs = []
        critical = [
            g for g in self._gaps.values() if g.severity == GapSeverity.CRITICAL
        ]
        high = [
            g for g in self._gaps.values() if g.severity == GapSeverity.HIGH
        ]
        if critical:
            recs.append(f"⚠️ {len(critical)} فجوات حرجة تحتاج إجراء فوري")
        if high:
            recs.append(f"⚡ {len(high)} فجوات عالية الأولوية")
        if not self._gaps:
            recs.append("✅ التغطية مقبولة — لا توجد فجوات حرجة")
        return recs

    def summary(self) -> Dict[str, Any]:
        """ملخص الفجوات."""
        return {
            "total_gaps": len(self._gaps),
            "by_category": {
                g: sum(1 for v in self._gaps.values() if v.category.value == g)
                for g in set(v.category.value for v in self._gaps.values())
            },
            "by_severity": {
                s: sum(1 for v in self._gaps.values() if v.severity.value == s)
                for s in set(v.severity.value for v in self._gaps.values())
            },
        }
