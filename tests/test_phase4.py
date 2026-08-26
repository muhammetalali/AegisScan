"""اختبارات المرحلة 4 — محركات التحليل الخمسة."""

import pytest
from pathlib import Path

from aegis.core.event_bus import EventBus
from aegis.engines.analysis.code_quality import CodeQualityEngine
from aegis.engines.analysis.runtime import RuntimeAnalysisEngine
from aegis.engines.analysis.performance import PerformanceAnalysisEngine
from aegis.engines.analysis.dep_risk import DependencyRiskEngine
from aegis.engines.analysis.config_check import ConfigurationCheckEngine
from aegis.models.evidence import Evidence, EvidenceCategory


# ─── fixtures مشتركة ──────────────────────────────────────

@pytest.fixture
async def bus():
    b = EventBus()
    await b.start()
    yield b
    await b.stop()


# ─── Code Quality ─────────────────────────────────────────

async def test_code_quality_detects_eval(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "bad.py")
    Path(f).write_text("result = eval(user_input)\n")
    engine = CodeQualityEngine(bus)
    evs = await engine.analyze_codebase(d, "sc_q1")
    assert any("eval" in e.description for e in evs)
    # تنظيف
    os.unlink(f); os.rmdir(d)


async def test_code_quality_detects_long_function(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "long.py")
    lines = ["def f():\n"] + ["    x = 1\n"] * 60
    Path(f).write_text("".join(lines))
    engine = CodeQualityEngine(bus)
    evs = await engine.analyze_codebase(d, "sc_q2")
    assert any("طويلة" in e.description for e in evs)
    os.unlink(f); os.rmdir(d)


async def test_code_quality_no_issues_on_clean_code(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "clean.py")
    Path(f).write_text("def add(a, b):\n    return a + b\n")
    engine = CodeQualityEngine(bus)
    evs = await engine.analyze_codebase(d, "sc_q3")
    assert len(evs) == 0
    os.unlink(f); os.rmdir(d)


# ─── Runtime Analysis ─────────────────────────────────────

async def test_runtime_detects_errors(bus):
    engine = RuntimeAnalysisEngine(bus)
    evs = await engine.analyze_log_content(
        "2024-01-01 ERROR: something failed\nTraceback (most recent call last):",
        "sc_r1",
    )
    assert len(evs) >= 1
    assert any("خطأ" in e.description for e in evs)


async def test_runtime_detects_auth_failure(bus):
    engine = RuntimeAnalysisEngine(bus)
    evs = await engine.analyze_log_content(
        "brute force attack detected for user admin\n"
        "login failed for user admin from 192.168.1.1",
        "sc_r2",
    )
    assert len(evs) >= 1


async def test_runtime_clean_logs(bus):
    engine = RuntimeAnalysisEngine(bus)
    evs = await engine.analyze_log_content(
        "INFO: Server started\nINFO: Listening on port 8080",
        "sc_r3",
    )
    assert len(evs) == 0


# ─── Performance ──────────────────────────────────────────

async def test_performance_detects_n_plus_one(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "nplus.py")
    code = """
for user_id in user_ids:
    user = db.execute("SELECT * FROM users WHERE id=?", user_id)
"""
    Path(f).write_text(code)
    engine = PerformanceAnalysisEngine(bus)
    evs = await engine.analyze_codebase(d, "sc_p1")
    assert any("N+1" in e.description for e in evs)
    os.unlink(f); os.rmdir(d)


async def test_performance_clean_code(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "ok.py")
    Path(f).write_text("x = 1\ny = 2\nprint(x + y)\n")
    engine = PerformanceAnalysisEngine(bus)
    evs = await engine.analyze_codebase(d, "sc_p2")
    assert len(evs) == 0
    os.unlink(f); os.rmdir(d)


# ─── Dependency Risk ──────────────────────────────────────

async def test_dep_risk_finds_requirements(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "requirements.txt")
    Path(f).write_text("flask==2.0\npytest==7.0\ncoverage==6.0\n")
    engine = DependencyRiskEngine(bus)
    evs = await engine.analyze_dependencies(d, "sc_d1")
    assert any("pytest" in e.description for e in evs)
    assert any("coverage" in e.description for e in evs)
    os.unlink(f); os.rmdir(d)


async def test_dep_risk_no_file(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    engine = DependencyRiskEngine(bus)
    evs = await engine.analyze_dependencies(d, "sc_d2")
    assert len(evs) == 0
    os.rmdir(d)


# ─── Configuration Check ──────────────────────────────────

async def test_config_check_detects_debug(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "settings.yaml")
    Path(f).write_text("DEBUG=true\nSECRET_KEY=super_secret_key_here\n")
    engine = ConfigurationCheckEngine(bus)
    evs = await engine.check_config(d, "sc_c1")
    assert any("DEBUG" in e.context.get("rule_id", "") for e in evs)
    assert any("SECRET_KEY" in e.context.get("rule_id", "") or "SECRET" in e.context.get("rule_id", "") for e in evs)
    os.unlink(f); os.rmdir(d)


async def test_config_check_clean(bus):
    """إعدادات آمنة — لا أدلة."""
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, "settings.yaml")
    Path(f).write_text("DEBUG=false\nPORT=8080\nHOST=localhost\n")
    engine = ConfigurationCheckEngine(bus)
    evs = await engine.check_config(d, "sc_c2")
    assert len(evs) == 0
    os.unlink(f); os.rmdir(d)


async def test_config_check_env_file(bus):
    import tempfile, os
    d = tempfile.mkdtemp()
    f = os.path.join(d, ".env")
    Path(f).write_text("ALLOWED_HOSTS=*\nCORS_ALLOW_ALL_ORIGINS=true\n")
    engine = ConfigurationCheckEngine(bus)
    evs = await engine.check_config(d, "sc_c3")
    assert len(evs) >= 1
    os.unlink(f); os.rmdir(d)
