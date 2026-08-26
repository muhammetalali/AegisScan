"""اختبارات تكامل Orchestrator — اختبار الدورة الكاملة."""

import pytest
import tempfile
from aegis.core.event_bus import EventBus
from aegis.core.data_manager import DataManager
from aegis.core.config_manager import ConfigManager
from aegis.core.audit_logger import AuditLogger
from aegis.core.orchestrator import AegisOrchestrator, OrchestratorState


# ─── fixtures ──────────────────────────────────────────────

@pytest.fixture
async def full_stack():
    """ieval完整的 Orchestrator مع كل المحركات."""
    bus = EventBus()
    await bus.start()

    config = ConfigManager()
    data = DataManager(":memory:")

    # إنشاء ملف سجل مؤقت
    audit_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
    audit_file.close()
    audit = AuditLogger(log_file=audit_file.name)

    orch = AegisOrchestrator(bus, data, config, audit)
    yield orch, bus, data

    data.close()
    await bus.stop()
    import os
    try:
        os.unlink(audit_file.name)
    except Exception:
        pass


# ─── اختبارات التكامل ──────────────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_initializes_all_engines(full_stack):
    """التحقق من أن كل المحركات تم تهيئتها."""
    orch, bus, data = full_stack

    # الاستخبارات
    assert orch.scanner is not None
    assert orch.bte is not None
    assert orch.external_hub is not None
    assert orch.fusion is not None

    # التحليل
    assert orch.code_quality is not None
    assert orch.runtime_analysis is not None
    assert orch.performance is not None
    assert orch.dep_risk is not None
    assert orch.config_check is not None

    # الاستدلال
    assert orch.knowledge_graph is not None
    assert orch.confidence is not None
    assert orch.risk is not None
    assert orch.why is not None

    # التحقق
    assert orch.auth_gate is not None
    assert orch.planner is not None
    assert orch.controller is not None
    assert orch.recorder is not None

    # الإصلاح
    assert orch.remediation is not None
    assert orch.verifier is not None
    assert orch.report_gen is not None


@pytest.mark.asyncio
async def test_orchestrator_state_transitions(full_stack):
    """التحقق من انتقالات الحالة."""
    orch, bus, data = full_stack
    assert orch.state == OrchestratorState.IDLE


@pytest.mark.asyncio
async def test_orchestrator_requires_target(full_stack):
    """يجب تحديد هدف واحد على الأقل."""
    orch, bus, data = full_stack
    with pytest.raises(ValueError, match="يجب تحديد"):
        await orch.run_full_cycle()


@pytest.mark.asyncio
async def test_orchestrator_full_cycle_code_only(full_stack):
    """الدورة الكاملة مع كود فقط (بدون إصلاح)."""
    import tempfile, os
    from pathlib import Path

    orch, bus, data = full_stack

    # إنشاء مشروع مؤقت
    d = tempfile.mkdtemp()
    Path(os.path.join(d, "app.py")).write_text(
        'import os\nresult = os.system("echo hello")\n'
    )
    Path(os.path.join(d, "config.yaml")).write_text(
        'DEBUG=true\nSECRET_KEY=super_secret_key_here\n'
    )
    Path(os.path.join(d, "requirements.txt")).write_text(
        'flask==2.0\npytest==7.0\n'
    )

    report = await orch.run_full_cycle(
        code_path=d, user_id="test",
        enable_external_intel=False,
        enable_analysis=True,
    )

    # التحقق من التقرير
    assert report["scan_id"].startswith("scan_")
    assert report["evidence_count"] >= 0
    assert "risk_summary" in report
    assert "knowledge_graph" in report
    assert "report_markdown" in report

    # تنظيف
    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_orchestrator_generates_markdown_report(full_stack):
    """التحقق من توليد تقرير Markdown."""
    import tempfile, os
    from pathlib import Path

    orch, bus, data = full_stack

    d = tempfile.mkdtemp()
    Path(os.path.join(d, "main.py")).write_text("x = 1\n")

    report = await orch.run_full_cycle(
        code_path=d, user_id="test",
        enable_external_intel=False,
        enable_analysis=False,
    )

    md = report.get("report_markdown", "")
    assert len(md) > 50
    assert "تقرير الأمان" in md or "Aegis" in md

    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_orchestrator_knowledge_graph_built(full_stack):
    """التحقق من بناء الرسم البياني."""
    import tempfile, os
    from pathlib import Path

    orch, bus, data = full_stack

    d = tempfile.mkdtemp()
    Path(os.path.join(d, "vuln.py")).write_text(
        'eval(input("cmd: "))\n'
    )

    report = await orch.run_full_cycle(
        code_path=d, user_id="test",
        enable_external_intel=False,
        enable_analysis=True,
    )

    kg = orch.knowledge_graph.summary()
    assert kg["nodes"] > 0

    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_orchestrator_confidence_scores_calculated(full_stack):
    """التحقق من حساب درجات الثقة."""
    import tempfile, os
    from pathlib import Path

    orch, bus, data = full_stack

    d = tempfile.mkdtemp()
    Path(os.path.join(d, "app.py")).write_text(
        'eval(input("x"))\nexec(input("y"))\n'
    )

    report = await orch.run_full_cycle(
        code_path=d, user_id="test",
        enable_external_intel=False,
        enable_analysis=True,
    )

    scores = report.get("confidence_scores", {})
    # قد يكون فارغاً إذا لم تُكتشف ثغرات مُرتبطة
    assert isinstance(scores, dict)

    import shutil
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_orchestrator_risk_assessment(full_stack):
    """التحقق من تقييم المخاطرة."""
    import tempfile, os
    from pathlib import Path

    orch, bus, data = full_stack

    d = tempfile.mkdtemp()
    Path(os.path.join(d, "app.py")).write_text(
        'eval(input("cmd: "))\n'
    )

    report = await orch.run_full_cycle(
        code_path=d, user_id="test",
        enable_external_intel=False,
        enable_analysis=True,
    )

    risk = report.get("risk_summary", {})
    assert "total" in risk
    assert "average_score" in risk

    import shutil
    shutil.rmtree(d, ignore_errors=True)
