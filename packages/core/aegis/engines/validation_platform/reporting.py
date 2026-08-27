"""Reporting Engine — محرك التقارير المحسّن.

يدعم تقارير فنية وإدارية بتنسيقات متعددة.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.reporting")


class ReportType(str, Enum):
    TECHNICAL = "technical"
    EXECUTIVE = "executive"
    COMPLIANCE = "compliance"
    REMEDIATION = "remediation"
    FULL = "full"


@dataclass
class ReportSection:
    """قسم في التقرير."""
    title: str
    content: str
    order: int = 0


@dataclass
class Report:
    """تقرير."""
    report_id: str
    report_type: ReportType
    title: str
    sections: List[ReportSection]
    metadata: Dict[str, Any] = field(default_factory=dict)
    generated_at: Optional[datetime] = None


class ReportingEngine:
    """محرك التقارير — يولّد تقارير شاملة."""

    name = "ReportingEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._reports: List[Report] = []

    async def generate_full_report(
        self,
        scan_id: str,
        scan_results: Dict[str, Any],
        validation_results: List[Dict[str, Any]],
        posture_data: Dict[str, Any],
        compliance_data: Dict[str, Any],
        attack_path_data: Dict[str, Any],
        evidence_graph_data: Dict[str, Any],
        knowledge_data: Dict[str, Any],
        control_data: Dict[str, Any],
        coverage_data: Dict[str, Any],
    ) -> Report:
        """تقرير شامل — يجمع كل النتائج."""
        sections = [
            ReportSection(
                title="ملخص تنفيذي",
                content=self._executive_summary(scan_results, posture_data),
                order=1,
            ),
            ReportSection(
                title="الثغرات المكتشفة",
                content=self._findings_section(scan_results),
                order=2,
            ),
            ReportSection(
                title="نتائج التحقق",
                content=self._validation_section(validation_results),
                order=3,
            ),
            ReportSection(
                title="فعالية الضوابط",
                content=self._control_section(control_data),
                order=4,
            ),
            ReportSection(
                title="تحليل مسارات الهجوم",
                content=self._attack_path_section(attack_path_data),
                order=5,
            ),
            ReportSection(
                title="الوضع الأمني",
                content=self._posture_section(posture_data),
                order=6,
            ),
            ReportSection(
                title="الامتثال",
                content=self._compliance_section(compliance_data),
                order=7,
            ),
            ReportSection(
                title="فجوات التغطية",
                content=self._coverage_section(coverage_data),
                order=8,
            ),
            ReportSection(
                title="المعرفة المكتسبة",
                content=self._knowledge_section(knowledge_data),
                order=9,
            ),
        ]

        report = Report(
            report_id=f"rpt_{scan_id}",
            report_type=ReportType.FULL,
            title=f"تقرير تحقق أمني شامل — {scan_id}",
            sections=sections,
            metadata={
                "scan_id": scan_id,
                "total_sections": len(sections),
            },
            generated_at=datetime.now(timezone.utc),
        )

        self._reports.append(report)
        return report

    async def to_markdown(self, report: Report) -> str:
        """تحويل التقرير إلى Markdown."""
        lines = [f"# {report.title}", ""]
        lines.append(f"**التاريخ:** {report.generated_at.isoformat()[:10] if report.generated_at else 'N/A'}")
        lines.append("")

        for section in sorted(report.sections, key=lambda s: s.order):
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.content)
            lines.append("")

        return "\n".join(lines)

    async def to_json(self, report: Report) -> str:
        """تحويل التقرير إلى JSON."""
        data = {
            "report_id": report.report_id,
            "type": report.report_type.value,
            "title": report.title,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None,
            "sections": [
                {"title": s.title, "content": s.content}
                for s in report.sections
            ],
            "metadata": report.metadata,
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def _executive_summary(self, results: Dict, posture: Dict) -> str:
        findings = results.get("total_findings", 0)
        risk = posture.get("overall_score", 0)
        return (
            f"إجمالي النتائج: {findings}\n"
            f"درجة الوضع الأمني: {risk}/100\n"
            f"المخاطر: {'عالية' if risk < 50 else 'مقبولة'}"
        )

    def _findings_section(self, results: Dict) -> str:
        lines = []
        for sev in ("critical", "high", "medium", "low"):
            count = results.get(f"{sev}_findings", 0)
            if count > 0:
                lines.append(f"- {sev}: {count}")
        return "\n".join(lines) if lines else "لا توجد نتائج"

    def _validation_section(self, validations: List[Dict]) -> str:
        confirmed = sum(1 for v in validations if v.get("status") == "confirmed")
        refuted = sum(1 for v in validations if v.get("status") == "refuted")
        return (
            f"مؤكدة: {confirmed}\n"
            f"مرفوضة (False Positives): {refuted}\n"
            f"نسبة التأكيد: {confirmed / max(confirmed + refuted, 1) * 100:.1f}%"
        )

    def _control_section(self, data: Dict) -> str:
        return (
            f"ضوابط مختبرة: {data.get('total_controls', 0)}\n"
            f"فعالة: {data.get('effective', 0)}\n"
            f"غير فعالة: {data.get('ineffective', 0)}"
        )

    def _attack_path_section(self, data: Dict) -> str:
        paths = data.get("total_paths", 0)
        critical = data.get("critical_paths", 0)
        return (
            f"مسارات مكتشفة: {paths}\n"
            f"مسارات حرجة: {critical}"
        )

    def _posture_section(self, data: Dict) -> str:
        score = data.get("overall_score", 0)
        rating = data.get("rating", "unknown")
        return f"النتيجة: {score}/100 — التصنيف: {rating}"

    def _compliance_section(self, data: Dict) -> str:
        return (
            f"نسبة الامتثال: {data.get('compliance_pct', 0)}%\n"
            f"انتهاكات: {data.get('non_compliant', 0)}"
        )

    def _coverage_section(self, data: Dict) -> str:
        return f"تغطية الكشف: {data.get('coverage_pct', 0)}%"

    def _knowledge_section(self, data: Dict) -> str:
        return (
            f"عناصر معرفة: {data.get('total_items', 0)}\n"
            f"دروس مستفادة: {data.get('lessons_learned', 0)}"
        )

    def summary(self) -> Dict[str, Any]:
        return {"total_reports": len(self._reports)}
