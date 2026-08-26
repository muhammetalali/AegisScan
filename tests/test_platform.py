"""اختبارات تكامل منصة التحقق الأمني — 15 محركاً مستقلاً."""

import pytest
import asyncio
from aegis.core.event_bus import EventBus


# ═══════════════════════════════════════════════════════
#  fixtures
# ═══════════════════════════════════════════════════════

@pytest.fixture
def bus():
    return EventBus()


# ═══════════════════════════════════════════════════════
#  1. Recon & Asset Discovery Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_recon_discover_from_code(bus):
    from aegis.engines.validation_platform.recon import ReconAssetDiscoveryEngine
    engine = ReconAssetDiscoveryEngine(bus)
    assets = await engine.discover_from_code("C:\\Users\\muham\\Desktop\\AegisScan-1\\aegis", "scan_test")
    assert isinstance(assets, list)
    summary = engine.summary()
    assert summary["total_assets"] >= 0


@pytest.mark.asyncio
async def test_recon_summary(bus):
    from aegis.engines.validation_platform.recon import ReconAssetDiscoveryEngine
    engine = ReconAssetDiscoveryEngine(bus)
    s = engine.summary()
    assert "total_assets" in s
    assert "by_type" in s


# ═══════════════════════════════════════════════════════
#  2. Evidence Collection Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_evidence_collect(bus):
    from aegis.engines.validation_platform.evidence_collection import (
        EvidenceCollectionEngine, EvidenceSource, EvidenceQuality,
    )
    engine = EvidenceCollectionEngine(bus)
    ev = await engine.collect_evidence(
        scan_id="s1", source=EvidenceSource.STATIC_ANALYSIS,
        category="injection", description="SQL injection found",
        confidence=0.8,
    )
    assert ev.evidence_id.startswith("ev_")
    assert ev.quality in (EvidenceQuality.HIGH, EvidenceQuality.MEDIUM)
    assert engine.quality_summary()["total"] == 1


@pytest.mark.asyncio
async def test_evidence_corroborate(bus):
    from aegis.engines.validation_platform.evidence_collection import (
        EvidenceCollectionEngine, EvidenceSource, EvidenceQuality,
    )
    engine = EvidenceCollectionEngine(bus)
    ev = await engine.collect_evidence(
        scan_id="s1", source=EvidenceSource.STATIC_ANALYSIS,
        category="injection", description="SQL injection",
        confidence=0.6,
    )
    await engine.corroborate(ev.evidence_id, EvidenceSource.CONFIG_CHECK)
    updated = engine.get_evidence(ev.evidence_id)
    assert updated.corroboration_count == 1
    assert updated.confidence > 0.6


@pytest.mark.asyncio
async def test_evidence_verified(bus):
    from aegis.engines.validation_platform.evidence_collection import (
        EvidenceCollectionEngine, EvidenceSource, EvidenceQuality,
    )
    engine = EvidenceCollectionEngine(bus)
    ev = await engine.collect_evidence(
        scan_id="s1", source=EvidenceSource.STATIC_ANALYSIS,
        category="injection", description="test",
        confidence=0.9,
    )
    await engine.corroborate(ev.evidence_id, EvidenceSource.CONFIG_CHECK)
    await engine.corroborate(ev.evidence_id, EvidenceSource.LOG_ANALYSIS)
    updated = engine.get_evidence(ev.evidence_id)
    assert updated.quality == EvidenceQuality.VERIFIED


# ═══════════════════════════════════════════════════════
#  3. Vulnerability Intelligence Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_vuln_intel_ingest(bus):
    from aegis.engines.validation_platform.vuln_intelligence import (
        VulnerabilityIntelligenceEngine, VulnIntelligence, VulnSeverity, ExploitAvailability,
    )
    engine = VulnerabilityIntelligenceEngine(bus)
    vuln = VulnIntelligence(
        vuln_id="v1", cve_id="CVE-2024-0001", title="Test Vuln",
        severity=VulnSeverity.HIGH, cvss_score=8.5,
        exploit_availability=ExploitAvailability.POC,
    )
    result = await engine.ingest_vuln(vuln)
    assert result.vuln_id == "v1"
    assert engine.summary()["total_vulns"] == 1


@pytest.mark.asyncio
async def test_vuln_intel_impact(bus):
    from aegis.engines.validation_platform.vuln_intelligence import (
        VulnerabilityIntelligenceEngine, VulnIntelligence, VulnSeverity, ExploitAvailability,
    )
    engine = VulnerabilityIntelligenceEngine(bus)
    vuln = VulnIntelligence(
        vuln_id="v2", cve_id=None, title="Critical Test",
        severity=VulnSeverity.CRITICAL, cvss_score=9.8,
        exploit_availability=ExploitAvailability.WEAPONIZED,
    )
    await engine.ingest_vuln(vuln)
    impact = await engine.assess_impact("v2", ["asset1"])
    assert impact.risk_score > 0
    assert impact.recommendation != ""


# ═══════════════════════════════════════════════════════
#  4. Validation Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_validation_validate(bus):
    from aegis.engines.validation_platform.validation import (
        ValidationEngine, ValidationScenario, ValidationMethod, ValidationStatus,
    )
    engine = ValidationEngine(bus)
    scenario = ValidationScenario(
        scenario_id="vs1", name="Test Validation",
        description="desc", method=ValidationMethod.PATTERN_MATCH,
        target="finding1",
    )
    result = await engine.validate(scenario)
    assert result.status in (ValidationStatus.INCONCLUSIVE, ValidationStatus.CONFIRMED, ValidationStatus.REFUTED)
    assert engine.summary()["total_validations"] == 1


# ═══════════════════════════════════════════════════════
#  5. Security Control Validation Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_control_validation(bus):
    from aegis.engines.validation_platform.control_validation import (
        SecurityControlValidationEngine, ControlType, TestVector, ControlEffectiveness,
    )
    engine = SecurityControlValidationEngine(bus)
    await engine.register_control("waf1", ControlType.WAF, "WAF-Prod")
    result = await engine.test_control("waf1", TestVector.SQL_INJECTION, "target1")
    assert result.detected is True
    assert result.effectiveness == ControlEffectiveness.EFFECTIVE
    assert engine.summary()["total_controls"] == 1


@pytest.mark.asyncio
async def test_control_validation_coverage(bus):
    from aegis.engines.validation_platform.control_validation import (
        SecurityControlValidationEngine, ControlType, TestVector,
    )
    engine = SecurityControlValidationEngine(bus)
    await engine.register_control("waf1", ControlType.WAF, "WAF")
    await engine.register_control("edr1", ControlType.EDR, "EDR")
    await engine.test_control("waf1", TestVector.SQL_INJECTION, "t1")
    await engine.test_control("edr1", TestVector.MALICIOUS_FILE, "t1")
    coverage = await engine.assess_coverage([TestVector.SQL_INJECTION, TestVector.MALICIOUS_FILE])
    assert "sql_injection" in coverage


# ═══════════════════════════════════════════════════════
#  6. Coverage Gap Analyzer
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_coverage_gap_analyze(bus):
    from aegis.engines.validation_platform.coverage_gap import CoverageGapAnalyzer
    engine = CoverageGapAnalyzer(bus)
    report = await engine.analyze(
        assets=[{"asset_id": "a1", "criticality": "critical"}],
        controls=[],
        findings=[{"title": "SQL Injection", "severity": "high", "affected_assets": ["a1"]}],
        scan_id="s1",
    )
    assert report.total_assets == 1
    assert len(report.gaps) >= 0


# ═══════════════════════════════════════════════════════
#  7. Attack Path Analyzer
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_attack_path_build_and_analyze(bus):
    from aegis.engines.validation_platform.attack_path import AttackPathAnalyzer
    engine = AttackPathAnalyzer(bus)
    await engine.build_graph(
        assets=[
            {"asset_id": "a1", "name": "WebApp", "environment": "prod"},
            {"asset_id": "a2", "name": "DB", "environment": "prod"},
        ],
        findings=[
            {"finding_id": "f1", "title": "SQLi", "severity": "high",
             "confidence": 0.8, "risk_score": 7.0, "affected_assets": ["a2"]},
        ],
        controls=[],
    )
    analysis = await engine.analyze(entry_points=["a1"])
    assert analysis.total_nodes == 3
    assert isinstance(analysis.paths, list)


# ═══════════════════════════════════════════════════════
#  8. Evidence Graph Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_evidence_graph_build(bus):
    from aegis.engines.validation_platform.evidence_graph import (
        EvidenceGraphEngine, GraphNodeType, GraphEdgeType,
    )
    engine = EvidenceGraphEngine(bus)
    await engine.build_from_results(
        assets=[{"asset_id": "a1", "name": "WebApp"}],
        findings=[{"finding_id": "f1", "title": "SQLi", "confidence": 0.8, "affected_assets": ["a1"]}],
        evidences=[{"evidence_id": "e1", "description": "Pattern match", "confidence": 0.7, "related_findings": ["f1"]}],
        remediations=[],
    )
    s = engine.summary()
    assert s["total_nodes"] >= 2


@pytest.mark.asyncio
async def test_evidence_graph_strength(bus):
    from aegis.engines.validation_platform.evidence_graph import (
        EvidenceGraphEngine, GraphNodeType, GraphEdgeType,
    )
    engine = EvidenceGraphEngine(bus)
    await engine.add_node("f1", GraphNodeType.FINDING, "SQLi", 0.8)
    await engine.add_node("e1", GraphNodeType.EVIDENCE, "Pattern", 0.7)
    await engine.add_edge("e1", "f1", GraphEdgeType.SUPPORTS)
    strength = await engine.calculate_evidence_strength("f1")
    assert strength["supporting_evidence"] == 1
    assert strength["verdict"] == "supported"


# ═══════════════════════════════════════════════════════
#  9. Knowledge Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_knowledge_add_and_query(bus):
    from aegis.engines.validation_platform.knowledge import KnowledgeEngine, KnowledgeType
    engine = KnowledgeEngine(bus)
    item = await engine.add_knowledge(
        knowledge_type=KnowledgeType.LESSON_LEARNED,
        title="SQL Injection Lesson",
        description="Always validate input",
        tags=["sql", "input"],
    )
    assert item.item_id.startswith("ki_")
    result = await engine.query(knowledge_type=KnowledgeType.LESSON_LEARNED)
    assert result.total == 1


@pytest.mark.asyncio
async def test_knowledge_apply(bus):
    from aegis.engines.validation_platform.knowledge import KnowledgeEngine, KnowledgeType
    engine = KnowledgeEngine(bus)
    item = await engine.add_knowledge(
        knowledge_type=KnowledgeType.REMEDIATION_PATTERN,
        title="Use parameterized queries",
        description="Fix SQL injection",
    )
    await engine.apply_knowledge(item.item_id, "s1", success=True)
    updated = engine.get_item(item.item_id)
    assert updated.times_applied == 1
    assert updated.success_rate == 1.0


# ═══════════════════════════════════════════════════════
#  10. Security Posture Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_posture_evaluate(bus):
    from aegis.engines.validation_platform.posture import SecurityPostureEngine, PostureRating
    engine = SecurityPostureEngine(bus)
    snapshot = await engine.evaluate(
        scan_results={
            "findings_by_severity": {"critical": 0, "high": 1, "medium": 3, "low": 5},
            "controls_tested": 5, "controls_effective": 4,
            "avg_confidence": 0.75, "coverage_pct": 80,
        },
        scan_id="s1",
    )
    assert snapshot.overall_score > 0
    assert snapshot.rating in list(PostureRating)
    assert len(snapshot.metrics) > 0


# ═══════════════════════════════════════════════════════
#  11. Policy & Compliance Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_compliance_check(bus):
    from aegis.engines.validation_platform.policy_compliance import (
        PolicyComplianceEngine, PolicyRule, ComplianceFramework, PolicyPriority,
    )
    engine = PolicyComplianceEngine(bus)
    await engine.add_rule(PolicyRule(
        rule_id="r1", framework=ComplianceFramework.NIST,
        control_id="AC-1", title="Access Control",
        description="desc", priority=PolicyPriority.MANDATORY,
        severity_threshold="high",
    ))
    report = await engine.check_compliance(
        findings=[{"finding_id": "f1", "severity": "critical", "title": "SQLi"}],
        framework=ComplianceFramework.NIST,
        scan_id="s1",
    )
    assert report.framework == ComplianceFramework.NIST


# ═══════════════════════════════════════════════════════
#  12. Digital Twin Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_twin_build_and_simulate(bus):
    from aegis.engines.validation_platform.twin_engine import (
        DigitalTwinEngine, TwinStatus, ChangeType, ChangeScenario,
    )
    engine = DigitalTwinEngine(bus)
    status = await engine.build_model(
        assets=[{"asset_id": "a1", "name": "WebApp"}],
        controls=[{"control_id": "c1", "name": "WAF", "protected_assets": ["a1"]}],
    )
    assert status == TwinStatus.READY

    scenario = ChangeScenario(
        scenario_id="sc1", change_type=ChangeType.PATCH,
        title="Update WAF rules", description="desc",
        affected_nodes=["c1"],
    )
    impact = await engine.simulate_change(scenario)
    assert impact.risk_reduction >= 0


# ═══════════════════════════════════════════════════════
#  13. Scenario Library
# ═══════════════════════════════════════════════════════

def test_scenario_library_defaults():
    from aegis.engines.validation_platform.scenarios import ScenarioLibrary
    from aegis.core.event_bus import EventBus
    lib = ScenarioLibrary(EventBus())
    assert len(lib.get_all()) >= 5
    assert lib.get_by_category("injection") != []
    sql = lib.search("SQL")
    assert len(sql) >= 1


# ═══════════════════════════════════════════════════════
#  14. Executive Dashboard
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_dashboard_generate(bus):
    from aegis.engines.validation_platform.dashboard import ExecutiveDashboard
    engine = ExecutiveDashboard(bus)
    summary = await engine.generate(
        scan_id="s1",
        findings=[{"severity": "critical"}, {"severity": "high"}, {"severity": "medium"}],
        validation_results=[{"status": "confirmed"}, {"status": "refuted"}],
        posture_data={"overall_score": 75, "rating": "good"},
        coverage_data={"coverage_pct": 85},
        compliance_data={"compliance_pct": 90, "non_compliant": 1},
        evidence_data={"total": 10},
    )
    assert summary.risk_score > 0
    assert len(summary.key_insights) > 0
    md = await engine.generate_markdown(summary)
    assert "تقرير لوحة القيادة الأمنية" in md


# ═══════════════════════════════════════════════════════
#  15. Reporting Engine
# ═══════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_reporting_full(bus):
    from aegis.engines.validation_platform.reporting import ReportingEngine
    engine = ReportingEngine(bus)
    report = await engine.generate_full_report(
        scan_id="s1",
        scan_results={"total_findings": 5, "critical_findings": 1, "high_findings": 2},
        validation_results=[{"status": "confirmed"}],
        posture_data={"overall_score": 70, "rating": "fair"},
        compliance_data={"compliance_pct": 85, "non_compliant": 2},
        attack_path_data={"total_paths": 3, "critical_paths": 1},
        evidence_graph_data={"total_nodes": 10},
        knowledge_data={"total_items": 5, "lessons_learned": 2},
        control_data={"total_controls": 3, "effective": 2, "ineffective": 1},
        coverage_data={"coverage_pct": 75},
    )
    assert len(report.sections) >= 8
    md = await engine.to_markdown(report)
    assert "تقرير تحقق أمني شامل" in md
    js = await engine.to_json(report)
    assert "s1" in js
