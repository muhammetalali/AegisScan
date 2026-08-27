"""Executive Dashboard — لوحة القيادة التنفيذية.

تقرير فني وإداري — تحول المنصة من اختبار اختراق إلى منصة تحقق أمني شاملة.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.dashboard")


@dataclass
class DashboardMetric:
    """مقياس في لوحة القيادة."""
    name: str
    value: Any
    unit: str = ""
    trend: str = "stable"
    target: Optional[float] = None
    status: str = "normal"


@dataclass
class ExecutiveSummary:
    """ملخص تنفيذي."""
    scan_id: str
    timestamp: str
    overall_risk: str
    risk_score: float
    total_findings: int
    critical_findings: int
    high_findings: int
    confirmed_findings: int
    false_positives: int
    coverage_pct: float
    posture_score: float
    compliance_pct: float
    metrics: List[DashboardMetric] = field(default_factory=list)
    key_insights: List[str] = field(default_factory=list)
    action_items: List[str] = field(default_factory=list)


class ExecutiveDashboard:
    """لوحة القيادة — تقارير فنية وإدارية."""

    name = "ExecutiveDashboard"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._reports: List[ExecutiveSummary] = []

    async def generate(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        validation_results: List[Dict[str, Any]],
        posture_data: Dict[str, Any],
        coverage_data: Dict[str, Any],
        compliance_data: Dict[str, Any],
        evidence_data: Dict[str, Any],
    ) -> ExecutiveSummary:
        """توليد ملخص تنفيذي."""
        # حساب الإحصائيات
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        confirmed = sum(
            1 for v in validation_results
            if v.get("status") == "confirmed"
        )
        false_pos = sum(
            1 for v in validation_results
            if v.get("status") == "refuted"
        )

        # حساب المخاطر
        risk_score = self._calc_risk_score(findings, confirmed)
        overall_risk = self._risk_label(risk_score)

        # المعايير
        metrics = [
            DashboardMetric(
                name="الثغرات الحرجة",
                value=critical,
                target=0,
                status="critical" if critical > 0 else "normal",
            ),
            DashboardMetric(
                name="الثغرات العالية",
                value=high,
                target=0,
                status="high" if high > 0 else "normal",
            ),
            DashboardMetric(
                name="النتائج المؤكدة",
                value=confirmed,
                status="normal",
            ),
            DashboardMetric(
                name="النتائج الكاذبة",
                value=false_pos,
                status="normal" if false_pos == 0 else "warning",
            ),
            DashboardMetric(
                name="تغطية الكشف",
                value=coverage_data.get("coverage_pct", 0),
                unit="%",
                target=90,
                status=(
                    "normal" if coverage_data.get("coverage_pct", 0) >= 90
                    else "warning"
                ),
            ),
            DashboardMetric(
                name="الوضع الأمني",
                value=posture_data.get("overall_score", 0),
                unit="/100",
                target=80,
                status=(
                    "normal" if posture_data.get("overall_score", 0) >= 80
                    else "warning"
                ),
            ),
            DashboardMetric(
                name="نسبة الامتثال",
                value=compliance_data.get("compliance_pct", 0),
                unit="%",
                target=100,
                status=(
                    "normal" if compliance_data.get("compliance_pct", 0) >= 90
                    else "warning"
                ),
            ),
        ]

        # الرؤى الرئيسية
        insights = self._generate_insights(
            critical, high, confirmed, false_pos, coverage_data, posture_data
        )

        # بنود الإجراء
        action_items = self._generate_action_items(
            findings, validation_results, coverage_data, compliance_data
        )

        report = ExecutiveSummary(
            scan_id=scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            overall_risk=overall_risk,
            risk_score=risk_score,
            total_findings=total,
            critical_findings=critical,
            high_findings=high,
            confirmed_findings=confirmed,
            false_positives=false_pos,
            coverage_pct=coverage_data.get("coverage_pct", 0),
            posture_score=posture_data.get("overall_score", 0),
            compliance_pct=compliance_data.get("compliance_pct", 0),
            metrics=metrics,
            key_insights=insights,
            action_items=action_items,
        )

        self._reports.append(report)

        await self.event_bus.publish(
            topic="dashboard.generated",
            payload={
                "scan_id": scan_id,
                "overall_risk": overall_risk,
                "risk_score": risk_score,
            },
            source=self.name,
        )
        return report

    async def generate_markdown(self, summary: ExecutiveSummary) -> str:
        """توليد تقرير Markdown تنفيذي."""
        lines = [
            f"# تقرير لوحة القيادة الأمنية",
            f"",
            f"**معرف الفحص:** {summary.scan_id}",
            f"**التاريخ:** {summary.timestamp[:10]}",
            f"**مستوى المخاطر:** {summary.overall_risk} ({summary.risk_score}/100)",
            f"",
            f"## ملخص النتائج",
            f"",
            f"| المقياس | القيمة |",
            f"|---|---|",
            f"| إجمالي النتائج | {summary.total_findings} |",
            f"| حرجة | {summary.critical_findings} |",
            f"| عالية | {summary.high_findings} |",
            f"| مؤكدة | {summary.confirmed_findings} |",
            f"| كاذبة | {summary.false_positives} |",
            f"",
            f"## مؤشرات الأداء",
            f"",
        ]

        for m in summary.metrics:
            target_str = f" (الهدف: {m.target})" if m.target else ""
            lines.append(f"- **{m.name}:** {m.value}{m.unit}{target_str}")

        lines.extend([
            f"",
            f"## الرؤى الرئيسية",
            f"",
        ])
        for insight in summary.key_insights:
            lines.append(f"- {insight}")

        lines.extend([
            f"",
            f"## بنود الإجراء",
            f"",
        ])
        for item in summary.action_items:
            lines.append(f"- {item}")

        return "\n".join(lines)

    async def generate_json(self, summary: ExecutiveSummary) -> str:
        """توليد تقرير JSON."""
        data = {
            "scan_id": summary.scan_id,
            "timestamp": summary.timestamp,
            "overall_risk": summary.overall_risk,
            "risk_score": summary.risk_score,
            "findings": {
                "total": summary.total_findings,
                "critical": summary.critical_findings,
                "high": summary.high_findings,
                "confirmed": summary.confirmed_findings,
                "false_positives": summary.false_positives,
            },
            "metrics": {
                "coverage_pct": summary.coverage_pct,
                "posture_score": summary.posture_score,
                "compliance_pct": summary.compliance_pct,
            },
            "key_insights": summary.key_insights,
            "action_items": summary.action_items,
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def _calc_risk_score(
        self, findings: List[Dict], confirmed: int
    ) -> float:
        """حساب درجة المخاطر."""
        if not findings:
            return 10.0
        crit = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        risk = min(crit * 20 + high * 10, 100)
        return round(max(risk, 10), 1)

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 80:
            return "حرج"
        if score >= 60:
            return "عالي"
        if score >= 40:
            return "متوسط"
        if score >= 20:
            return "منخفض"
        return "آمن"

    def _generate_insights(
        self, critical, high, confirmed, false_pos,
        coverage, posture
    ) -> List[str]:
        insights = []
        if critical > 0:
            insights.append(f"⚠️ {critical} ثغرات حرجة تحتاج إجراء فوري")
        if false_pos > 0:
            insights.append(
                f"🔍 {false_pos} نتائج كاذبة — تحسين دقة الكشف"
            )
        cov = coverage.get("coverage_pct", 0)
        if cov < 70:
            insights.append(f"📊 تغطية الكشف منخفضة ({cov:.0f}%)")
        score = posture.get("overall_score", 0)
        if score >= 80:
            insights.append("✅ الوضع الأمني مقبول")
        elif score < 50:
            insights.append("⚠️ الوضع الأمني يحتاج تحسينات جوهرية")
        if not insights:
            insights.append("ℹ️ لا توجد ملاحظات رئيسية")
        return insights

    def _generate_action_items(
        self, findings, validations, coverage, compliance
    ) -> List[str]:
        items = []
        crit = [f for f in findings if f.get("severity") == "critical"]
        if crit:
            items.append(f"إصلاح {len(crit)} ثغرات حرجة فوراً")
        non_comp = compliance.get("non_compliant", 0)
        if non_comp > 0:
            items.append(f"معالجة {non_comp} انتهاك للامتثال")
        cov = coverage.get("coverage_pct", 0)
        if cov < 90:
            items.append("تحسين تغطية الضوابط")
        if not items:
            items.append("استمرار المراقبة الدورية")
        return items

    def get_latest(self) -> Optional[ExecutiveSummary]:
        return self._reports[-1] if self._reports else None

    def summary(self) -> Dict[str, Any]:
        return {"total_reports": len(self._reports)}
