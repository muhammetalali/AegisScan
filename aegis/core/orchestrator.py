"""المنسق الرئيسي — Aegis Orchestrator (v0.3.0).

يدور الدورة الكاملة عبر الطبقات السبع + الطبقة الهجومية:
  ① جمع الأدلة (داخلي + خارجي)
  ② تحليل الأدلة (كود + أداء + تبعيات + إعدادات + سجلات)
  ③ ربط + قصة هجوم
  ④ بناء الرسم البياني + درجة الثقة + المخاطرة + التفسير
  ⑤ التحقق المنضبط + تسجيل
  ⑥ اختبار في التوأم الرقمي (اختياري)
  ⑦ توليد الإصلاح + التحقق منه
  ⑧ إنشاء التقرير النهائي
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.audit_logger import AuditLogger
from aegis.core.config_manager import ConfigManager
from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus

# ── الاستخبارات ──
from aegis.engines.intelligence.aegis_scan import AegisScan
from aegis.engines.intelligence.bte import BTE
from aegis.engines.intelligence.external_hub import ExternalIntelligenceHub
from aegis.engines.intelligence.fusion import EvidenceFusionEngine
from aegis.engines.intelligence.trust import SourceTrustFramework

# ── التحليل ──
from aegis.engines.analysis.code_quality import CodeQualityEngine
from aegis.engines.analysis.runtime import RuntimeAnalysisEngine
from aegis.engines.analysis.performance import PerformanceAnalysisEngine
from aegis.engines.analysis.dep_risk import DependencyRiskEngine
from aegis.engines.analysis.config_check import ConfigurationCheckEngine

# ── الاستدلال ──
from aegis.engines.inference.knowledge_graph import KnowledgeGraphEngine
from aegis.engines.inference.confidence import ConfidenceScoringEngine
from aegis.engines.inference.risk import RiskAssessmentEngine
from aegis.engines.inference.why_engine import WhyEngine

# ── التحقق ──
from aegis.engines.validation.authorization import AuthorizationGate, ActionLevel
from aegis.engines.validation.planner import ExecutionPlanner, PlannedAction
from aegis.engines.validation.controller import ExecutionController
from aegis.engines.validation.recorder import ActionRecorder
from aegis.engines.validation.replay import ReplayEngine

# ── الإصلاح ──
from aegis.engines.remediation.orchestrator import RemediationOrchestrator
from aegis.engines.remediation.verifier import RemediationVerifier
from aegis.engines.remediation.report import ReportGenerator

# ── العمليات ──
from aegis.engines.operational.correlation import CorrelationEngine
from aegis.engines.operational.soc import SOCEngine

# ── الطبقة الهجومية (التوأم الرقمي) ──
from aegis.engines.offensive.twin import DigitalTwin, TwinConfig
from aegis.engines.offensive.aepex import AePEX
from aegis.engines.offensive.verifier import VerificationEngine

# ── النماذج ──
from aegis.models.scan import Scan, ScanType
from aegis.models.evidence import Evidence
from aegis.models.finding import Finding

logger = logging.getLogger("aegis.orchestrator")


class OrchestratorState(str, Enum):
    IDLE = "idle"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    INFERRING = "inferring"
    CORRELATING = "correlating"
    VALIDATING = "validating"
    TESTING_TWIN = "testing_twin"
    REMEDIATING = "remediating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class AegisOrchestrator:
    """المايسترو: يقود الدورة الكاملة عبر الطبقات السبع."""

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

        threshold = config.get("correlation.confidence_threshold", 0.60)

        # ── الطبقات الأساسية ──
        self.scanner = AegisScan(event_bus, data_manager)
        self.bte = BTE(event_bus, data_manager)
        self.correlation = CorrelationEngine(event_bus, data_manager, threshold)
        self.soc = SOCEngine(event_bus, data_manager)

        # ── Phase 3: الاستخبارات الخارجية ──
        self.trust = SourceTrustFramework()
        self.external_hub = ExternalIntelligenceHub(event_bus, self.trust)
        self.fusion = EvidenceFusionEngine(event_bus, self.trust)

        # ── Phase 4: محركات التحليل ──
        self.code_quality = CodeQualityEngine(event_bus)
        self.runtime_analysis = RuntimeAnalysisEngine(event_bus)
        self.performance = PerformanceAnalysisEngine(event_bus)
        self.dep_risk = DependencyRiskEngine(event_bus)
        self.config_check = ConfigurationCheckEngine(event_bus)

        # ── Phase 5: الاستدلال ──
        self.knowledge_graph = KnowledgeGraphEngine(event_bus)
        self.confidence = ConfidenceScoringEngine(event_bus)
        self.risk = RiskAssessmentEngine(event_bus)
        self.why = WhyEngine(event_bus)

        # ── Phase 6: التحقق المنضبط ──
        self.auth_gate = AuthorizationGate()
        self.planner = ExecutionPlanner(self.auth_gate)
        self.controller = ExecutionController(event_bus)
        self.recorder = ActionRecorder(event_bus)
        self.replay = ReplayEngine(event_bus, self.recorder)

        # ── الطبقة الهجومية: التوأم الرقمي ──
        twin_config = TwinConfig()
        self.twin = DigitalTwin(twin_config)
        self.aepex = AePEX(self.twin, audit_logger)
        self.twin_verifier = VerificationEngine()

        # ── Phase 7: الإصلاح ──
        self.remediation = RemediationOrchestrator(event_bus)
        self.verifier = RemediationVerifier(event_bus)
        self.report_gen = ReportGenerator(event_bus)

        self.state = OrchestratorState.IDLE
        self._abort_requested = False

    async def run_full_cycle(
        self,
        code_path: Optional[str] = None,
        target_url: Optional[str] = None,
        user_id: str = "cli",
        enable_external_intel: bool = True,
        enable_analysis: bool = True,
        enable_remediation: bool = False,
    ) -> Dict[str, Any]:
        """الدورة الكاملة: ① جمع ← ② تحليل ← ③ استدلال ← ④ تحقق ← ⑤ إصلاح ← ⑥ تقرير"""
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
        self._abort_requested = False

        self.audit_logger.log(
            user_id=user_id, action="scan.started",
            target=scan.target, result="in_progress", extra={"scan_id": scan.id},
        )
        await self.event_bus.publish(
            topic="scan.started",
            payload={"scan_id": scan.id, "code_path": code_path, "target_url": target_url},
            source="Orchestrator",
        )

        try:
            # ══════════════════════════════════════════════
            # ① جمع الأدلة (داخلي + خارجي + تحليل)
            # ══════════════════════════════════════════════
            self.state = OrchestratorState.COLLECTING
            internal_evidences: List[Evidence] = []
            external_evidences: List[Evidence] = []
            analysis_evidences: List[Evidence] = []

            # ── أدلة داخلية (AegisScan + BTE) ──
            if code_path:
                evs = await self.scanner.analyze_project(code_path, scan.id)
                internal_evidences.extend(evs)
            if target_url:
                bte_ev = await self.bte.analyze_target(target_url, scan.id)
                if bte_ev:
                    internal_evidences.append(bte_ev)

            if self._abort_requested:
                scan.fail()
                return self._report(scan.id, aborted=True)

            # ── استخبارات خارجية ──
            if enable_external_intel:
                try:
                    ext_evs = await self.external_hub.collect_all(
                        target=scan.target, scan_id=scan.id,
                    )
                    external_evidences.extend(ext_evs)
                except Exception as exc:
                    logger.warning("استخبارات خارجية فشلت: %s", exc)

            # ── تحليل الكود (Phase 4) ──
            if enable_analysis and code_path:
                self.state = OrchestratorState.ANALYZING
                try:
                    cq = await self.code_quality.analyze_codebase(code_path, scan.id)
                    analysis_evidences.extend(cq)
                except Exception as exc:
                    logger.warning("CodeQuality فشل: %s", exc)

                try:
                    pf = await self.performance.analyze_codebase(code_path, scan.id)
                    analysis_evidences.extend(pf)
                except Exception as exc:
                    logger.warning("Performance فشل: %s", exc)

                try:
                    dr = await self.dep_risk.analyze_dependencies(code_path, scan.id)
                    analysis_evidences.extend(dr)
                except Exception as exc:
                    logger.warning("DepRisk فشل: %s", exc)

                try:
                    cc = await self.config_check.check_config(code_path, scan.id)
                    analysis_evidences.extend(cc)
                except Exception as exc:
                    logger.warning("ConfigCheck فشل: %s", exc)

            # ── تحليل السجلات (Runtime) ──
            if enable_analysis:
                self.state = OrchestratorState.ANALYZING
                try:
                    import os
                    for log_file in ["app.log", "error.log", "server.log", "access.log"]:
                        log_path = os.path.join(code_path or ".", log_file) if code_path else log_file
                        if os.path.exists(log_path):
                            rt = await self.runtime_analysis.analyze_logs(log_path, scan.id)
                            analysis_evidences.extend(rt)
                except Exception as exc:
                    logger.warning("RuntimeAnalysis فشل: %s", exc)

            # ══════════════════════════════════════════════
            # ② دمج الأدلة
            # ══════════════════════════════════════════════
            all_evidences = await self.fusion.fuse(
                internal_evidences, external_evidences
            )
            # إضافة أدلة التحليل (لا تحتاج دمج — من مصادر موثوقة)
            all_evidences.extend(analysis_evidences)

            # ══════════════════════════════════════════════
            # ③ الربط والقصة (Operational)
            # ══════════════════════════════════════════════
            self.state = OrchestratorState.CORRELATING
            await self.event_bus.wait_until_idle()
            findings = await self.correlation.correlate_scan(scan.id)
            finding_dicts = [f.to_dict() for f in findings]
            story = await self.soc.build_story(scan.id, finding_dicts)

            # ══════════════════════════════════════════════
            # ④ الاستدلال (KG + ثقة + مخاطرة + تفسير)
            # ══════════════════════════════════════════════
            self.state = OrchestratorState.INFERRING

            # بناء الرسم البياني
            for ev in all_evidences:
                await self.knowledge_graph.add_evidence(ev)
            for f in findings:
                await self.knowledge_graph.add_finding(f)

            # حساب الثقة لكل ثغرة
            confidences: Dict[str, float] = {}
            for f in findings:
                evs_for_finding = [
                    e for e in all_evidences
                    if e.scan_id == scan.id
                ]
                conf = await self.confidence.score_finding(f, evs_for_finding)
                confidences[f.id] = conf
                f.confidence_score = conf

            # تقييم المخاطرة
            risk_assessments = await self.risk.assess_all(findings, confidences)

            # توليد التفسيرات
            explanations: List[Dict[str, Any]] = []
            for f in findings:
                evs_for_f = [
                    e for e in all_evidences if e.scan_id == scan.id
                ]
                risk_assess = next(
                    (r for r in risk_assessments if r["finding_id"] == f.id),
                    None,
                )
                exp = await self.why.explain_finding(f, evs_for_f, risk_assess)
                explanations.append(exp)

            # ══════════════════════════════════════════════
            # ⑤ التحقق المنضبط
            # ══════════════════════════════════════════════
            self.state = OrchestratorState.VALIDATING

            action = PlannedAction(
                action_id=f"scan_{scan.id}",
                action_type="scan.complete",
                level=ActionLevel.READ,
                target=scan.target,
            )
            plan = self.planner.create_plan(f"plan_{scan.id}", [action])
            auth_result = self.planner.authorize_plan(plan)

            await self.recorder.record_action(
                action_id=f"scan_{scan.id}",
                plan_id=plan.plan_id,
                action_type="scan.complete",
                level="read",
                target=scan.target,
                parameters={"evidence_count": len(all_evidences)},
                result={"findings": len(findings)},
                success=True,
            )

            # ══════════════════════════════════════════════
            # ⑥ اختبار في التوأم الرقمي (اختياري — يحتاج Docker)
            # ══════════════════════════════════════════════
            twin_test_results: Optional[Dict[str, Any]] = None
            if self.twin.is_safe_to_test:
                self.state = OrchestratorState.TESTING_TWIN
                try:
                    twin_test_results = {
                        "twin_status": "active",
                        "sandbox_ready": True,
                        "verifier_stats": self.twin_verifier.stats(),
                    }
                    await self.event_bus.publish(
                        topic="twin.test_completed",
                        payload=twin_test_results,
                        source="Orchestrator",
                    )
                except Exception as exc:
                    logger.warning("اختبار التوأم فشل: %s", exc)
                    twin_test_results = {"twin_status": "error", "error": str(exc)}
            else:
                twin_test_results = {
                    "twin_status": "inactive",
                    "sandbox_ready": False,
                    "reason": f"Docker غير متاح أو التوأم غير جاهز (حالة: {self.twin.state.value})",
                }

            # ══════════════════════════════════════════════
            # ⑦ الإصلاح (اختياري)
            # ══════════════════════════════════════════════
            remediation_list: List[Any] = []
            if enable_remediation:
                self.state = OrchestratorState.REMEDIATING
                for f in findings:
                    if f.severity.value in ("critical", "high"):
                        try:
                            rem = await self.remediation.generate_remediation(f)
                            if rem:
                                rem = await self.remediation.test_remediation(rem.id)
                                verification = await self.verifier.verify(rem)
                                if verification["safe"]:
                                    rem = await self.remediation.approve_remediation(rem.id)
                                remediation_list.append(rem)
                        except Exception as exc:
                            logger.warning("إصلاح %s فشل: %s", f.id, exc)

            # ══════════════════════════════════════════════
            # ⑦ التقرير النهائي
            # ══════════════════════════════════════════════
            self.state = OrchestratorState.REPORTING
            scan.evidence_count = len(all_evidences)
            scan.finding_count = len(findings)
            scan.complete()
            self.data_manager.save_scan(scan.to_dict())

            risk_summary = self.risk.get_risk_summary(risk_assessments)
            why_summary = await self.why.explain_risk_level(risk_assessments)
            kg_summary = self.knowledge_graph.summary()
            recorder_summary = self.recorder.get_summary()

            report_text = await self.report_gen.generate(
                scan_id=scan.id,
                findings=findings,
                evidences=all_evidences,
                risk_assessments=risk_assessments,
                explanations=explanations,
                remediations=remediation_list,
                format="markdown",
            )

            self.state = OrchestratorState.COMPLETED

            report = {
                **self._report(
                    scan.id, findings=finding_dicts,
                    story=story.to_dict() if story else None,
                    remediations=[r.to_dict() for r in remediation_list] if remediation_list else [],
                ),
                "target": scan.target,
                "evidence_count": len(all_evidences),
                "external_evidence_count": len(external_evidences),
                "analysis_evidence_count": len(analysis_evidences),
                "duration_seconds": scan.duration_seconds,
                "risk_summary": risk_summary,
                "risk_explanation": why_summary,
                "knowledge_graph": kg_summary,
                "confidence_scores": confidences,
                "recorder_summary": recorder_summary,
                "report_markdown": report_text,
                "authorization": auth_result,
                "twin_test": twin_test_results,
                "replay_available": True,
            }

            self.audit_logger.log(
                user_id=user_id, action="scan.completed",
                target=scan.target, result="success",
                extra={
                    "scan_id": scan.id,
                    "findings": len(findings),
                    "evidence": len(all_evidences),
                    "risk_avg": risk_summary.get("average_score", 0),
                },
            )
            await self.event_bus.publish(
                topic="scan.completed",
                payload={
                    "scan_id": scan.id,
                    "findings": len(findings),
                    "evidence": len(all_evidences),
                },
                source="Orchestrator",
            )
            return report

        except Exception as exc:
            logger.exception("فشل الدورة الكاملة")
            scan.fail()
            self.data_manager.save_scan(scan.to_dict())
            self.audit_logger.log(
                user_id=user_id, action="scan.failed",
                target=scan.target, result=str(exc),
            )
            self.state = OrchestratorState.FAILED
            raise

    async def abort(self) -> None:
        """مفتاح الإيقاف الفوري."""
        logger.warning("طلب إيقاف فوري!")
        self._abort_requested = True

    @staticmethod
    def _report(
        scan_id: str,
        findings: Optional[list] = None,
        story: Optional[dict] = None,
        remediations: Optional[list] = None,
        aborted: bool = False,
    ) -> Dict[str, Any]:
        findings = findings or []
        severity_dist: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_dist[sev] = severity_dist.get(sev, 0) + 1

        generated_at = datetime.now(timezone.utc).isoformat()
        if aborted:
            return {
                "scan_id": scan_id, "status": "aborted",
                "generated_at": generated_at,
                "recommendations": ["تم إلغاء الفحص بواسطة المستخدم."],
            }

        recommendations: list = []
        for f in findings:
            if f.get("severity") in ("critical", "high"):
                recommendations.append(
                    f"عاجل — {f.get('title')}: إصلاح خلال 24 ساعة"
                )
        if not recommendations:
            recommendations.append("لا ثغرات حرجة — استمر بالفحص الدوري")

        return {
            "scan_id": scan_id,
            "generated_at": generated_at,
            "summary": {
                "total_findings": len(findings),
                "remediations_generated": len(remediations or []),
            },
            "severity_distribution": severity_dist,
            "attack_story": story,
            "findings": findings,
            "recommendations": list(dict.fromkeys(recommendations)),
        }
