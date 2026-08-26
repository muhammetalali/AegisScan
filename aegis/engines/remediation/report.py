"""Report Generator — مولّد التقارير.

يولّد تقارير أمنية بتنسيقات متعددة (Markdown, JSON).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence
from aegis.models.finding import Finding, Severity
from aegis.models.remediation import Remediation

logger = logging.getLogger("aegis.remediation.report")

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ReportGenerator:
    """مولّد التقارير — يُنتج تقارير أمنية شاملة."""

    name = "ReportGenerator"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def generate(
        self,
        scan_id: str,
        findings: List[Finding],
        evidences: List[Evidence],
        risk_assessments: Optional[List[Dict[str, Any]]] = None,
        explanations: Optional[List[Dict[str, Any]]] = None,
        remediations: Optional[List[Remediation]] = None,
        format: str = "markdown",
    ) -> str:
        """توليد تقرير كامل."""
        if format == "json":
            return await self._generate_json(
                scan_id, findings, evidences,
                risk_assessments, explanations, remediations,
            )
        return await self._generate_markdown(
            scan_id, findings, evidences,
            risk_assessments, explanations, remediations,
        )

    async def _generate_markdown(
        self,
        scan_id: str,
        findings: List[Finding],
        evidences: List[Evidence],
        risk_assessments: Optional[List[Dict[str, Any]]],
        explanations: Optional[List[Dict[str, Any]]],
        remediations: Optional[List[Remediation]],
    ) -> str:
        """تقرير Markdown."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 5),
        )

        # إحصائيات
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        lines = [
            f"# تقرير الأمان — {scan_id}",
            f"**التاريخ:** {now}",
            f"**إجمالي الثغرات:** {len(findings)}",
            f"**إجمالي الأدلة:** {len(evidences)}",
            "",
            "## ملخص الخطورة",
            "",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count:
                lines.append(f"- **{sev.upper()}**: {count}")

        lines.extend(["", "## الثغرات المكتشفة", ""])

        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"### {i}. {f.title}")
            lines.append(f"- **الخطورة:** {f.severity.value}")
            lines.append(f"- **الثقة:** {f.confidence_score:.0%}")

            # شرح
            if explanations:
                exp = next(
                    (e for e in explanations if e.get("finding_id") == f.id),
                    None,
                )
                if exp:
                    lines.append(f"- **التوضيح:** {exp.get('severity_explanation', '')}")

            # إصلاح
            if remediations:
                rem = next(
                    (r for r in remediations if r.finding_id == f.id),
                    None,
                )
                if rem:
                    lines.append(f"- **الإصلاح:** {rem.status.value} (ثقة {rem.confidence:.0%})")

            lines.append("")

        # الأدلة
        lines.extend(["## الأدلة الداعمة", ""])
        for ev in evidences[:20]:  # أقصى 20
            lines.append(
                f"- [{ev.source_tool}] {ev.description[:100]} "
                f"(ثقة: {ev.confidence_weight:.0%})"
            )

        lines.extend(["", "---", f"*تقرير مُولّد بواسطة Aegis v0.2.0*"])

        report = "\n".join(lines)

        await self.event_bus.publish(
            topic="report.generated",
            payload={"scan_id": scan_id, "format": "markdown", "length": len(report)},
            source=self.name,
        )
        return report

    async def _generate_json(
        self,
        scan_id: str,
        findings: List[Finding],
        evidences: List[Evidence],
        risk_assessments: Optional[List[Dict[str, Any]]],
        explanations: Optional[List[Dict[str, Any]]],
        remediations: Optional[List[Remediation]],
    ) -> str:
        """تقرير JSON."""
        data = {
            "scan_id": scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(findings),
                "total_evidences": len(evidences),
                "by_severity": {},
            },
            "findings": [f.to_dict() for f in findings],
            "evidences": [e.to_dict() for e in evidences],
            "risk_assessments": risk_assessments or [],
            "explanations": explanations or [],
            "remediations": [r.to_dict() for r in (remediations or [])],
        }

        # إحصائيات الخطورة
        for f in findings:
            sev = f.severity.value
            data["summary"]["by_severity"][sev] = (
                data["summary"]["by_severity"].get(sev, 0) + 1
            )

        report = json.dumps(data, indent=2, ensure_ascii=False, default=str)

        await self.event_bus.publish(
            topic="report.generated",
            payload={"scan_id": scan_id, "format": "json", "length": len(report)},
            source=self.name,
        )
        return report
