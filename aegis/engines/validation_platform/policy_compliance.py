"""Policy & Compliance Engine — محرك السياسات والامتثال.

يربط كل نتيجة بسياسات الشركة ويبين متطلبات المعالجة.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.compliance")


class ComplianceFramework(str, Enum):
    NIST = "nist_800_53"
    ISO27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    CIS = "cis_controls"
    CUSTOM = "custom"


class ComplianceStatus(str, Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class PolicyPriority(str, Enum):
    MANDATORY = "mandatory"
    IMPORTANT = "important"
    RECOMMENDED = "recommended"


@dataclass
class PolicyRule:
    """قاعدة سياسة."""
    rule_id: str
    framework: ComplianceFramework
    control_id: str
    title: str
    description: str
    priority: PolicyPriority = PolicyPriority.IMPORTANT
    check_type: str = ""  # vulnerability, configuration, access, etc.
    severity_threshold: str = "high"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceResult:
    """نتيجة الامتثال."""
    rule_id: str
    finding_id: str
    status: ComplianceStatus
    framework: ComplianceFramework
    control_id: str
    evidence: str = ""
    remediation_deadline: str = ""
    details: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReport:
    """تقرير الامتثال."""
    framework: ComplianceFramework
    total_rules: int = 0
    compliant: int = 0
    non_compliant: int = 0
    partial: int = 0
    compliance_percentage: float = 0.0
    results: List[ComplianceResult] = field(default_factory=list)
    gaps: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class PolicyComplianceEngine:
    """محرك السياسات والامتثال — يربط النتائج بالمعايير."""

    name = "PolicyComplianceEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._rules: Dict[str, PolicyRule] = {}
        self._results: Dict[str, ComplianceResult] = {}
        self._by_framework: Dict[str, List[str]] = {}

    async def add_rule(self, rule: PolicyRule) -> None:
        """إضافة قاعدة سياسة."""
        self._rules[rule.rule_id] = rule
        self._by_framework.setdefault(rule.framework.value, []).append(rule.rule_id)

    async def check_compliance(
        self,
        findings: List[Dict[str, Any]],
        framework: ComplianceFramework,
        scan_id: str,
    ) -> ComplianceReport:
        """فحص الامتثال حسب معيار معين."""
        framework_rules = [
            self._rules[rid]
            for rid in self._by_framework.get(framework.value, [])
        ]

        results: List[ComplianceResult] = []
        for rule in framework_rules:
            for finding in findings:
                result = self._evaluate_rule(rule, finding, scan_id)
                if result:
                    results.append(result)
                    self._results[f"{rule.rule_id}_{finding.get('finding_id', '')}"] = result

        compliant = sum(1 for r in results if r.status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for r in results if r.status == ComplianceStatus.NON_COMPLIANT)
        partial = sum(1 for r in results if r.status == ComplianceStatus.PARTIAL)
        total = compliant + non_compliant + partial

        gaps = [
            {
                "rule_id": r.rule_id,
                "control_id": r.control_id,
                "finding_id": r.finding_id,
                "status": r.status.value,
            }
            for r in results if r.status == ComplianceStatus.NON_COMPLIANT
        ]

        recommendations = self._generate_recommendations(results, framework)

        report = ComplianceReport(
            framework=framework,
            total_rules=len(framework_rules),
            compliant=compliant,
            non_compliant=non_compliant,
            partial=partial,
            compliance_percentage=round(
                (compliant / max(total, 1)) * 100, 1
            ),
            results=results,
            gaps=gaps,
            recommendations=recommendations,
        )

        await self.event_bus.publish(
            topic="compliance.checked",
            payload={
                "framework": framework.value,
                "compliance_pct": report.compliance_percentage,
                "gaps": len(gaps),
            },
            source=self.name,
        )
        return report

    async def check_all_frameworks(
        self, findings: List[Dict[str, Any]], scan_id: str
    ) -> Dict[str, ComplianceReport]:
        """فحص الامتثال بجميع المعايير."""
        reports = {}
        for fw_str in self._by_framework:
            try:
                fw = ComplianceFramework(fw_str)
                reports[fw_str] = await self.check_compliance(
                    findings, fw, scan_id
                )
            except (ValueError, KeyError):
                continue
        return reports

    async def get_remediation_deadlines(
        self, results: List[ComplianceResult]
    ) -> Dict[str, str]:
        """حساب مواعيد المعالجة."""
        deadlines = {}
        for result in results:
            if result.status == ComplianceStatus.NON_COMPLIANT:
                rule = self._rules.get(result.rule_id)
                if rule:
                    if rule.priority == PolicyPriority.MANDATORY:
                        deadlines[result.rule_id] = "7 أيام"
                    elif rule.priority == PolicyPriority.IMPORTANT:
                        deadlines[result.rule_id] = "30 يوم"
                    else:
                        deadlines[result.rule_id] = "90 يوم"
        return deadlines

    def _evaluate_rule(
        self, rule: PolicyRule, finding: Dict[str, Any], scan_id: str
    ) -> Optional[ComplianceResult]:
        """تقييم قاعدة مع نتيجة."""
        finding_severity = finding.get("severity", "medium")
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        # إذا كانت شدة الثغرة تتجاوز العتبة
        if severity_order.get(finding_severity, 0) >= severity_order.get(
            rule.severity_threshold, 3
        ):
            return ComplianceResult(
                rule_id=rule.rule_id,
                finding_id=finding.get("finding_id", ""),
                status=ComplianceStatus.NON_COMPLIANT,
                framework=rule.framework,
                control_id=rule.control_id,
                evidence=finding.get("title", ""),
                details=f"الثغرة تنتهك {rule.control_id}: {rule.title}",
            )
        return None

    def _generate_recommendations(
        self, results: List[ComplianceResult], framework: ComplianceFramework
    ) -> List[str]:
        recs = []
        non_comp = [r for r in results if r.status == ComplianceStatus.NON_COMPLIANT]
        if non_comp:
            recs.append(
                f"⚠️ {len(non_comp)} انتهاك لمعايير {framework.value} — معالجة فورية"
            )
        else:
            recs.append(f"✅ متوافق مع {framework.value}")
        return recs

    def summary(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "total_results": len(self._results),
            "frameworks": list(self._by_framework.keys()),
        }
