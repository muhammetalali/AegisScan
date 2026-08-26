"""اختبارات المرحلة 7 — الإصلاح والتقرير."""

import pytest
from aegis.core.event_bus import EventBus
from aegis.engines.remediation.orchestrator import RemediationOrchestrator
from aegis.engines.remediation.verifier import RemediationVerifier
from aegis.engines.remediation.report import ReportGenerator
from aegis.models.finding import Finding, Severity
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType
from aegis.models.remediation import (
    Remediation, RemediationMethod, RemediationStatus, RemediationTestResult,
)


# ─── fixtures ──────────────────────────────────────────────

@pytest.fixture
async def bus():
    b = EventBus()
    await b.start()
    yield b
    await b.stop()


def _finding(title="SQL Injection", sev=Severity.HIGH):
    return Finding(
        scan_id="sc1", title=title, severity=sev, confidence_score=0.7,
        description="Test finding for remediation testing phase 7",
        evidence_ids=["ev_1", "ev_2"],
    )


def _ev(tool="Tool1", cat=EvidenceCategory.INJECTION):
    return Evidence(
        scan_id="sc1", source_tool=tool, evidence_type=EvidenceType.AST,
        category=cat, description="SQL injection in query string",
        confidence_weight=0.7, location="db.py:10",
    )


def _remediation(finding_id="f1", status=RemediationStatus.TEST_PASSED):
    return Remediation(
        finding_id=finding_id,
        method=RemediationMethod.PATTERN_BASED,
        generated_patch="cursor.execute(param_query)",
        old_code_snippet="cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")",
        file_path="db.py",
        line_start=10,
        line_end=10,
        confidence=0.8,
        status=status,
        test_results=[
            RemediationTestResult(test_type="syntax", passed=True),
            RemediationTestResult(test_type="security", passed=True),
        ],
    )


# ─── Remediation Orchestrator ──────────────────────────────

@pytest.mark.asyncio
async def test_orchestrator_generate(bus):
    orch = RemediationOrchestrator(bus)

    async def pattern_gen(finding):
        return {
            "patch": "safe_query(param)",
            "old_code": "unsafe_query(f)",
            "file_path": "db.py",
            "line_start": 10,
            "line_end": 10,
            "confidence": 0.7,
        }

    orch.register_generator("pattern", pattern_gen)
    f = _finding()
    rem = await orch.generate_remediation(f)

    assert rem is not None
    assert rem.finding_id == f.id
    assert rem.status == RemediationStatus.GENERATED
    assert rem.confidence == 0.7


@pytest.mark.asyncio
async def test_orchestrator_test_passed(bus):
    orch = RemediationOrchestrator(bus)

    async def pattern_gen(finding):
        return {"patch": "safe_query()"}
    orch.register_generator("pattern", pattern_gen)

    async def syntax_test(rem):
        return RemediationTestResult(test_type="syntax", passed=True, details="OK")
    orch.register_tester(syntax_test)

    f = _finding()
    rem = await orch.generate_remediation(f)
    rem = await orch.test_remediation(rem.id)
    assert rem.status == RemediationStatus.TEST_PASSED


@pytest.mark.asyncio
async def test_orchestrator_test_failed(bus):
    orch = RemediationOrchestrator(bus)

    async def pattern_gen(finding):
        return {"patch": "bad_patch"}
    orch.register_generator("pattern", pattern_gen)

    async def failing_test(rem):
        return RemediationTestResult(test_type="security", passed=False, details="FAIL")
    orch.register_tester(failing_test)

    f = _finding()
    rem = await orch.generate_remediation(f)
    rem = await orch.test_remediation(rem.id)
    assert rem.status == RemediationStatus.TEST_FAILED


@pytest.mark.asyncio
async def test_orchestrator_approve_and_apply(bus):
    orch = RemediationOrchestrator(bus)

    async def pattern_gen(finding):
        return {"patch": "fixed_code"}
    orch.register_generator("pattern", pattern_gen)

    async def ok_test(rem):
        return RemediationTestResult(test_type="unit", passed=True)
    orch.register_tester(ok_test)

    f = _finding()
    rem = await orch.generate_remediation(f)
    rem = await orch.test_remediation(rem.id)
    rem = await orch.approve_remediation(rem.id)
    assert rem.status == RemediationStatus.APPROVED

    rem = await orch.apply_remediation(rem.id)
    assert rem.status == RemediationStatus.APPLIED


@pytest.mark.asyncio
async def test_orchestrator_summary(bus):
    orch = RemediationOrchestrator(bus)

    async def gen(f):
        return {"patch": "x"}
    orch.register_generator("pattern", gen)

    f = _finding()
    await orch.generate_remediation(f)
    summary = orch.summary()
    assert summary["total"] == 1
    assert "generated" in summary["by_status"]


# ─── Remediation Verifier ──────────────────────────────────

@pytest.mark.asyncio
async def test_verifier_safe_remediation(bus):
    verifier = RemediationVerifier(bus)
    rem = _remediation()
    result = await verifier.verify(rem)
    assert result["safe"]
    assert len(result["checks"]) >= 2


@pytest.mark.asyncio
async def test_verifier_low_confidence(bus):
    verifier = RemediationVerifier(bus)
    rem = _remediation()
    rem.confidence = 0.3  # منخفضة جداً
    result = await verifier.verify(rem)
    assert not result["safe"]


@pytest.mark.asyncio
async def test_verifier_no_tests(bus):
    verifier = RemediationVerifier(bus)
    rem = _remediation()
    rem.test_results = []
    result = await verifier.verify(rem)
    assert not result["safe"]
    assert "اختبارات" in result["checks"][0]["details"]


@pytest.mark.asyncio
async def test_verifier_custom_check(bus):
    verifier = RemediationVerifier(bus)

    async def custom_check(rem, ctx):
        return {"name": "custom", "passed": True, "details": "All good"}
    verifier.register_check(custom_check)

    rem = _remediation()
    result = await verifier.verify(rem)
    assert any(c["name"] == "custom" for c in result["checks"])


# ─── Report Generator ──────────────────────────────────────

@pytest.mark.asyncio
async def test_report_markdown(bus):
    gen = ReportGenerator(bus)
    f1 = _finding(title="SQL Injection", sev=Severity.HIGH)
    f2 = _finding(title="XSS Vulnerability", sev=Severity.MEDIUM)
    ev1 = _ev(tool="AegisScan")
    ev2 = _ev(tool="BTE", cat=EvidenceCategory.AUTHENTICATION)

    report = await gen.generate(
        scan_id="sc_report1",
        findings=[f1, f2],
        evidences=[ev1, ev2],
        format="markdown",
    )
    assert "# تقرير الأمان" in report
    assert "SQL Injection" in report
    assert "HIGH" in report.upper() or "high" in report


@pytest.mark.asyncio
async def test_report_json(bus):
    gen = ReportGenerator(bus)
    f = _finding()
    ev = _ev()

    report = await gen.generate(
        scan_id="sc_json1",
        findings=[f],
        evidences=[ev],
        format="json",
    )
    import json
    data = json.loads(report)
    assert data["scan_id"] == "sc_json1"
    assert data["summary"]["total_findings"] == 1


@pytest.mark.asyncio
async def test_report_with_remediations(bus):
    gen = ReportGenerator(bus)
    f = _finding()
    rem = _remediation(finding_id=f.id)

    report = await gen.generate(
        scan_id="sc_rem1",
        findings=[f],
        evidences=[],
        remediations=[rem],
        format="markdown",
    )
    assert "test_passed" in report
