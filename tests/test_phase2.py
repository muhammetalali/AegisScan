"""اختبارات المرحلة 2 — البنية التحتية الجديدة (Protocols, Repositories, Registry)."""

import pytest

from aegis.core.data_manager import DataManager
from aegis.core.repositories import EvidenceRepository, FindingRepository, ScanRepository
from aegis.core.capability_registry import CapabilityRegistry, EngineCapability, EngineType
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType
from aegis.models.finding import Finding, Severity


# ─── Data Repositories ────────────────────────────────────────

def _make_ev(scan_id: str = "sc_r1", tool: str = "TestTool") -> dict:
    e = Evidence(
        scan_id=scan_id, source_tool=tool, evidence_type=EvidenceType.AST,
        category=EvidenceCategory.INJECTION,
        description="دليل اختباري طويل بما يكفي للتحقق من المستودعات",
    )
    return e.to_dict()


def test_evidence_repository_save_and_get():
    dm = DataManager(":memory:")
    repo = EvidenceRepository(dm)
    ev = _make_ev()
    eid = repo.save(ev)
    assert eid == ev["id"]
    results = repo.get_by_scan("sc_r1")
    assert len(results) == 1
    assert results[0]["id"] == ev["id"]
    assert repo.count("sc_r1") == 1
    dm.close()


def test_evidence_repository_by_hash():
    dm = DataManager(":memory:")
    repo = EvidenceRepository(dm)
    ev = _make_ev()
    repo.save(ev)
    found = repo.get_by_hash(ev["content_hash"])
    assert found is not None
    assert found["id"] == ev["id"]
    dm.close()


def test_finding_repository_save_and_get():
    dm = DataManager(":memory:")
    repo = FindingRepository(dm)
    ev1 = _make_ev(tool="Tool1")
    ev2 = _make_ev(tool="Tool2")
    dm.save_evidence(ev1)
    dm.save_evidence(ev2)
    f = Finding(
        scan_id="sc_r2", title="ثغرة اختبار للمستودع",
        severity=Severity.HIGH, confidence_score=0.8,
        description="ثغرة اختبارية للتحقق من مستودع الثغرات",
        evidence_ids=[ev1["id"], ev2["id"]],
    )
    fid = repo.save(f.to_dict())
    assert fid == f.id
    results = repo.get_by_scan("sc_r2")
    assert len(results) == 1
    dm.close()


def test_scan_repository():
    dm = DataManager(":memory:")
    repo = ScanRepository(dm)
    scan = {"id": "scan_1", "target": "test", "scan_type": "full"}
    repo.save(scan)
    found = repo.get("scan_1")
    assert found is not None
    assert found["target"] == "test"
    assert repo.count() == 1
    dm.close()


# ─── Capability Registry ──────────────────────────────────────

def test_registry_register_and_get():
    reg = CapabilityRegistry()
    cap = EngineCapability(
        name="AegisScan", version="0.2.0",
        engine_type=EngineType.INTELLIGENCE,
        description="Static code analysis",
    )
    reg.register(cap)
    assert reg.get("AegisScan") is cap
    assert len(reg.list_all()) == 1


def test_registry_list_by_type():
    reg = CapabilityRegistry()
    reg.register(EngineCapability(
        name="Scan1", version="1.0", engine_type=EngineType.INTELLIGENCE))
    reg.register(EngineCapability(
        name="Scan2", version="1.0", engine_type=EngineType.INTELLIGENCE))
    reg.register(EngineCapability(
        name="Corr1", version="1.0", engine_type=EngineType.CORRELATION))
    intel = reg.list_by_type(EngineType.INTELLIGENCE)
    assert len(intel) == 2
    corr = reg.list_by_type(EngineType.CORRELATION)
    assert len(corr) == 1


def test_registry_health_check():
    reg = CapabilityRegistry()
    reg.register(EngineCapability(
        name="E1", version="1.0", engine_type=EngineType.ANALYSIS, health="ok"))
    reg.register(EngineCapability(
        name="E2", version="1.0", engine_type=EngineType.ANALYSIS, health="degraded"))
    h = reg.health_check()
    assert h["E1"] == "ok"
    assert h["E2"] == "degraded"


def test_registry_summary():
    reg = CapabilityRegistry()
    reg.register(EngineCapability(
        name="A", version="1.0", engine_type=EngineType.INTELLIGENCE))
    reg.register(EngineCapability(
        name="B", version="2.0", engine_type=EngineType.CORRELATION))
    s = reg.summary()
    assert s["total"] == 2
    assert s["by_type"]["intelligence"] == 1
    assert s["by_type"]["correlation"] == 1


def test_registry_remove():
    reg = CapabilityRegistry()
    reg.register(EngineCapability(
        name="X", version="1.0", engine_type=EngineType.OFFENSIVE))
    assert reg.remove("X") is True
    assert reg.get("X") is None
    assert reg.remove("X") is False  # غير موجود


# ─── Engine Protocols (runtime_checkable) ──────────────────────

def test_engines_have_required_attributes():
    from aegis.engines.intelligence.aegis_scan import AegisScan
    from aegis.engines.intelligence.bte import BTE
    from aegis.engines.operational.correlation import CorrelationEngine
    from aegis.engines.operational.soc import SOCEngine

    # كل المحركات تملك name + الدوال الأساسية
    assert hasattr(AegisScan, "name")
    assert hasattr(AegisScan, "analyze_project")
    assert hasattr(BTE, "name")
    assert hasattr(BTE, "analyze_target")
    assert hasattr(CorrelationEngine, "name")
    assert hasattr(CorrelationEngine, "correlate_scan")
    assert hasattr(SOCEngine, "name")
    assert hasattr(SOCEngine, "build_story")
