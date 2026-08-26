"""Platform Orchestrator — المنسق الرئيسي لمنصة التحقق الأمني (v1.0).

يُكمل الدورة الكاملة عبر 10 مراحل:
  ① الاستطلاع واكتشاف الأصول
  ② تحليل الثغرات والإعدادات
  ③ استخبارات التهديدات
  ④ الربط والاستنتاج
  ⑤ التحقق الأمني بيئة آمنة
  ⑥ إدارة المعرفة
  ⑦ مساعد الذكاء الاصطناعي
  ⑧ قياس الوضع الأمني
  ⑨ النموذج الافتراضي (Digital Twin)
  ⑩ منصة القرار الأمني
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.core.audit_logger import AuditLogger
from aegis.core.config_manager import ConfigManager
from aegis.core.data_manager import DataManager

# ── المحركات الأصلية ──
from aegis.core.orchestrator import AegisOrchestrator

# ── المحركات الجديدة: Validation Platform ──
from aegis.engines.validation_platform.recon import (
    ReconAssetDiscoveryEngine, AssetCriticality, AssetType,
)
from aegis.engines.validation_platform.evidence_collection import (
    EvidenceCollectionEngine, EvidenceQuality, EvidenceSource,
)
from aegis.engines.validation_platform.vuln_intelligence import (
    VulnerabilityIntelligenceEngine, VulnSeverity, VulnIntelligence,
)
from aegis.engines.validation_platform.validation import (
    ValidationEngine, ValidationMethod, ValidationStatus,
)
from aegis.engines.validation_platform.control_validation import (
    SecurityControlValidationEngine, ControlType, TestVector, ControlEffectiveness,
)
from aegis.engines.validation_platform.coverage_gap import (
    CoverageGapAnalyzer, GapSeverity,
)
from aegis.engines.validation_platform.attack_path import (
    AttackPathAnalyzer, NodeType, EdgeType,
)
from aegis.engines.validation_platform.evidence_graph import (
    EvidenceGraphEngine, GraphNodeType, GraphEdgeType,
)
from aegis.engines.validation_platform.knowledge import (
    KnowledgeEngine, KnowledgeType,
)
from aegis.engines.validation_platform.posture import (
    SecurityPostureEngine, PostureRating,
)
from aegis.engines.validation_platform.policy_compliance import (
    PolicyComplianceEngine, ComplianceFramework, ComplianceStatus,
)
from aegis.engines.validation_platform.twin_engine import (
    DigitalTwinEngine, TwinStatus, ChangeType,
)
from aegis.engines.validation_platform.scenarios import ScenarioLibrary
from aegis.engines.validation_platform.dashboard import ExecutiveDashboard
from aegis.engines.validation_platform.reporting import ReportingEngine, ReportType

from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType
from aegis.models.finding import Finding
from aegis.models.scan import Scan, ScanType

logger = logging.getLogger("aegis.platform_orchestrator")


class PlatformState(str, Enum):
    IDLE = "idle"
    RECON = "recon"
    ANALYZING = "analyzing"
    INTEL = "intelligence"
    CORRELATING = "correlating"
    VALIDATING = "validating"
    KNOWLEDGE = "knowledge"
    AI_EXPLAIN = "ai_explain"
    POSTURE = "posture"
    TWIN = "twin"
    DECISION = "decision"
    COMPLETED = "completed"
    FAILED = "failed"


class PlatformOrchestrator:
    """منسق منصة التحقق الأمني — يقود 10 مراحل."""

    def __init__(
        self,
        event_bus: EventBus,
        data_manager: DataManager,
        config: ConfigManager,
        audit_logger: AuditLogger,
    ) -> None:
        self.event_bus = event_bus
        self.data_manager = data_manager
        self.config = config
        self.audit_logger = audit_logger

        # ── المنسق الأساسي ──
        self.core = AegisOrchestrator(event_bus, data_manager, config, audit_logger)

        # ── المرحلة 1: الاستطلاع ──
        self.recon = ReconAssetDiscoveryEngine(event_bus)

        # ── المرحلة 1 (مكمّل): جمع الأدلة ──
        self.evidence_collector = EvidenceCollectionEngine(event_bus)

        # ── المرحلة 2+3: استخبارات الثغرات ──
        self.vuln_intel = VulnerabilityIntelligenceEngine(event_bus)

        # ── المرحلة 4: التحقق ──
        self.validation = ValidationEngine(event_bus)

        # ── المرحلة 4 (مكمّل): فعالية الضوابط ──
        self.control_validation = SecurityControlValidationEngine(event_bus)

        # ── المرحلة 4 (مكمّل): فجوات التغطية ──
        self.coverage_gap = CoverageGapAnalyzer(event_bus)

        # ── المرحلة 4 (مكمّل): تحليل مسارات الهجوم ──
        self.attack_path = AttackPathAnalyzer(event_bus)

        # ── المرحلة 5: Evidence Graph ──
        self.evidence_graph = EvidenceGraphEngine(event_bus)

        # ── المرحلة 6: إدارة المعرفة ──
        self.knowledge = KnowledgeEngine(event_bus)

        # ── المرحلة 7: مساعد AI ──
        # مدمج في WhyEngine الأساسي

        # ── المرحلة 8: الوضع الأمني ──
        self.posture = SecurityPostureEngine(event_bus)

        # ── المرحلة 8 (مكمّل): السياسات ──
        self.compliance = PolicyComplianceEngine(event_bus)

        # ── المرحلة 9: Digital Twin المحسّن ──
        self.twin_engine = DigitalTwinEngine(event_bus)

        # ── المرحلة 10: مكتبة السيناريوهات ──
        self.scenarios = ScenarioLibrary(event_bus)

        # ── المرحلة 10 (مكمّل): لوحة القيادة ──
        self.dashboard = ExecutiveDashboard(event_bus)

        # ── المرحلة 10 (مكمّل): التقارير ──
        self.reporting = ReportingEngine(event_bus)

        self.state = PlatformState.IDLE

    async def run_full_cycle(
        self,
        code_path: Optional[str] = None,
        target_url: Optional[str] = None,
        user_id: str = "cli",
        enable_external_intel: bool = True,
        enable_analysis: bool = True,
        enable_validation: bool = True,
        enable_remediation: bool = False,
    ) -> Dict[str, Any]:
        """الدورة الكاملة عبر 10 مراحل."""
        if not code_path and not target_url:
            raise ValueError("يجب تحديد مسار كود أو عنوان URL على الأقل")

        scan = Scan(
            id=f"scan_{uuid.uuid4().hex[:12]}",
            scan_type=(
                ScanType.FULL if code_path and target_url
                else ScanType.CODE_ONLY if code_path
                else ScanType.URL_ONLY
            ),
            target=target_url or str(code_path),
            triggered_by=user_id,
        )
        scan.start()

        self.audit_logger.log(
            user_id=user_id, action="platform.started",
            target=scan.target, result="in_progress",
            extra={"scan_id": scan.id},
        )
        await self.event_bus.publish(
            topic="platform.started",
            payload={"scan_id": scan.id},
            source="PlatformOrchestrator",
        )

        try:
            # ══════════════════════════════════════════════
            # ① الاستطلاع واكتشاف الأصول
            # ══════════════════════════════════════════════
            self.state = PlatformState.RECON
            discovered_assets = []
            if code_path:
                discovered_assets = await self.recon.discover_from_code(
                    code_path, scan.id
                )

            # ══════════════════════════════════════════════
            # ② التحليل الأساسي (يستخدم المحركات الأصلية)
            # ══════════════════════════════════════════════
            self.state = PlatformState.ANALYZING
            core_result = await self.core.run_full_cycle(
                code_path=code_path,
                target_url=target_url,
                user_id=user_id,
                enable_external_intel=enable_external_intel,
                enable_analysis=enable_analysis,
                enable_remediation=enable_remediation,
            )

            findings = core_result.get("findings", [])
            evidence_count = core_result.get("evidence_count", 0)

            # ══════════════════════════════════════════════
            # ③ استخبارات التهديدات
            # ══════════════════════════════════════════════
            self.state = PlatformState.INTEL
            for f_dict in findings:
                from aegis.engines.validation_platform.vuln_intelligence import (
                    VulnIntelligence as VulnIntel, VulnSeverity as VS,
                    ExploitAvailability,
                )
                sev_map = {"critical": VS.CRITICAL, "high": VS.HIGH, "medium": VS.MEDIUM, "low": VS.LOW}
                vuln = VulnIntel(
                    vuln_id=f_dict.get("finding_id", ""),
                    cve_id=None,
                    title=f_dict.get("title", ""),
                    severity=sev_map.get(f_dict.get("severity", "medium"), VS.MEDIUM),
                    cvss_score=f_dict.get("risk_score", 5.0),
                    exploit_availability=ExploitAvailability.NONE,
                    source="internal_analysis",
                )
                await self.vuln_intel.ingest_vuln(vuln)

            # ══════════════════════════════════════════════
            # ④ الربط والاستنتاج + التحقق
            # ══════════════════════════════════════════════
            self.state = PlatformState.CORRELATING

            # بناء Evidence Graph
            asset_dicts = [
                {
                    "asset_id": a.asset_id,
                    "name": a.name,
                    "criticality": a.criticality.value,
                }
                for a in discovered_assets
            ]
            await self.evidence_graph.build_from_results(
                assets=asset_dicts,
                findings=findings,
                evidences=[],
                remediations=core_result.get("remediations", []),
            )

            # تحليل مسارات الهجوم
            await self.attack_path.build_graph(
                assets=asset_dicts,
                findings=findings,
                controls=[],
            )
            attack_path_analysis = await self.attack_path.analyze()

            # ══════════════════════════════════════════════
            # ⑤ التحقق الأمني
            # ══════════════════════════════════════════════
            validation_results = []
            if enable_validation:
                self.state = PlatformState.VALIDATING
                for f_dict in findings[:5]:  # أول 5 نتائج
                    from aegis.engines.validation_platform.validation import (
                        ValidationScenario,
                    )
                    scenario = ValidationScenario(
                        scenario_id=f"vs_{f_dict.get('finding_id', '')}",
                        name=f"تحقق من {f_dict.get('title', '')}",
                        description="تحقق تلقائي",
                        method=ValidationMethod.PATTERN_MATCH,
                        target=f_dict.get("finding_id", ""),
                    )
                    result = await self.validation.validate(scenario)
                    validation_results.append({
                        "validation_id": result.validation_id,
                        "status": result.status.value,
                        "confidence": result.confidence,
                    })

            # ══════════════════════════════════════════════
            # ⑥ إدارة المعرفة
            # ══════════════════════════════════════════════
            self.state = PlatformState.KNOWLEDGE
            for f_dict in findings:
                if f_dict.get("severity") in ("critical", "high"):
                    await self.knowledge.add_knowledge(
                        knowledge_type=KnowledgeType.LESSON_LEARNED,
                        title=f"ثغرة {f_dict.get('severity')}: {f_dict.get('title', '')}",
                        description=f"تم اكتشاف نتيجة {f_dict.get('severity')}",
                        source_scan=scan.id,
                        tags=[f_dict.get("severity", ""), "auto_detected"],
                    )

            # ══════════════════════════════════════════════
            # ⑦ مساعد AI — مدمج في WhyEngine
            # ══════════════════════════════════════════════
            self.state = PlatformState.AI_EXPLAIN
            explanations = core_result.get("risk_explanation", {})

            # ══════════════════════════════════════════════
            # ⑧ قياس الوضع الأمني
            # ══════════════════════════════════════════════
            self.state = PlatformState.POSTURE
            severity_dist = core_result.get("severity_distribution", {})
            posture_snapshot = await self.posture.evaluate(
                scan_results={
                    "findings_by_severity": severity_dist,
                    "total_findings": len(findings),
                    "controls_tested": 0,
                    "controls_effective": 0,
                    "avg_confidence": core_result.get("confidence_scores", {})
                        and sum(core_result.get("confidence_scores", {}).values())
                        / max(len(core_result.get("confidence_scores", {})), 1)
                        or 0.5,
                    "coverage_pct": 70.0,
                },
                scan_id=scan.id,
            )

            # فحص الامتثال
            compliance_reports = {}
            for fw_str in ("nist_800_53", "iso_27001", "pci_dss"):
                try:
                    from aegis.engines.validation_platform.policy_compliance import (
                        ComplianceFramework,
                    )
                    fw = ComplianceFramework(fw_str)
                    comp_report = await self.compliance.check_compliance(
                        findings=findings,
                        framework=fw,
                        scan_id=scan.id,
                    )
                    compliance_reports[fw_str] = {
                        "compliance_pct": comp_report.compliance_percentage,
                        "non_compliant": comp_report.non_compliant,
                    }
                except Exception:
                    pass

            # ══════════════════════════════════════════════
            # ⑨ Digital Twin
            # ══════════════════════════════════════════════
            self.state = PlatformState.TWIN
            twin_status = await self.twin_engine.build_model(
                assets=asset_dicts,
                controls=[],
            )

            # ══════════════════════════════════════════════
            # ⑩ منصة القرار — لوحة القيادة + التقرير
            # ══════════════════════════════════════════════
            self.state = PlatformState.DECISION

            posture_data = {
                "overall_score": posture_snapshot.overall_score,
                "rating": posture_snapshot.rating.value,
            }
            coverage_data = {"coverage_pct": 70.0}
            first_compliance = next(iter(compliance_reports.values()), {})
            evidence_data = {"total": evidence_count}

            exec_summary = await self.dashboard.generate(
                scan_id=scan.id,
                findings=findings,
                validation_results=validation_results,
                posture_data=posture_data,
                coverage_data=coverage_data,
                compliance_data=first_compliance,
                evidence_data=evidence_data,
            )

            # التقرير الشامل
            full_report = await self.reporting.generate_full_report(
                scan_id=scan.id,
                scan_results={
                    "total_findings": len(findings),
                    **{f"{k}_findings": v for k, v in severity_dist.items()},
                },
                validation_results=validation_results,
                posture_data=posture_data,
                compliance_data=first_compliance,
                attack_path_data={
                    "total_paths": len(attack_path_analysis.paths),
                    "critical_paths": len(attack_path_analysis.critical_paths),
                },
                evidence_graph_data=self.evidence_graph.summary(),
                knowledge_data=self.knowledge.summary(),
                control_data=self.control_validation.summary(),
                coverage_data=coverage_data,
            )

            report_markdown = await self.reporting.to_markdown(full_report)
            exec_markdown = await self.dashboard.generate_markdown(exec_summary)

            self.state = PlatformState.COMPLETED
            scan.complete()

            result = {
                **core_result,
                "platform_version": "1.0.0",
                "platform_state": self.state.value,
                # المرحلة 1
                "discovered_assets": [
                    {"asset_id": a.asset_id, "name": a.name, "type": a.asset_type.value}
                    for a in discovered_assets
                ],
                "recon_summary": self.recon.summary(),
                # المرحلة 3
                "vuln_intel_summary": self.vuln_intel.summary(),
                # المرحلة 4
                "validation_summary": self.validation.summary(),
                "attack_paths": {
                    "total": len(attack_path_analysis.paths),
                    "critical": len(attack_path_analysis.critical_paths),
                    "highest_risk": attack_path_analysis.highest_risk,
                    "recommendations": attack_path_analysis.recommendations,
                },
                # المرحلة 5
                "evidence_graph": self.evidence_graph.summary(),
                # المرحلة 6
                "knowledge_summary": self.knowledge.summary(),
                # المرحلة 8
                "posture": posture_data,
                "compliance": compliance_reports,
                # المرحلة 9
                "twin_engine": self.twin_engine.summary(),
                # المرحلة 10
                "executive_summary": {
                    "overall_risk": exec_summary.overall_risk,
                    "risk_score": exec_summary.risk_score,
                    "key_insights": exec_summary.key_insights,
                    "action_items": exec_summary.action_items,
                },
                "report_markdown": report_markdown,
                "executive_dashboard": exec_markdown,
            }

            self.audit_logger.log(
                user_id=user_id, action="platform.completed",
                target=scan.target, result="success",
                extra={"scan_id": scan.id, "findings": len(findings)},
            )
            await self.event_bus.publish(
                topic="platform.completed",
                payload={"scan_id": scan.id, "findings": len(findings)},
                source="PlatformOrchestrator",
            )

            return result

        except Exception as exc:
            logger.exception("فشل دورة المنصة")
            scan.fail()
            self.state = PlatformState.FAILED
            self.audit_logger.log(
                user_id=user_id, action="platform.failed",
                target=scan.target, result=str(exc),
            )
            raise

    async def abort(self) -> None:
        """إيقاف فوري."""
        await self.core.abort()
