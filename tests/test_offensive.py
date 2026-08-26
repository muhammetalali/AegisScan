"""اختبارات الطبقة 3 — التوأم الرقمي (وحدات بدون Docker + تكامل شرطي)."""

import pytest

from aegis.core.exceptions import SafetyViolationError
from aegis.engines.offensive.twin import (
    DigitalTwin,
    TwinConfig,
    TwinState,
    validate_compose_security,
)
from aegis.engines.offensive.base_module import BaseTestModule, TestResult
from aegis.engines.offensive.verifier import VerificationEngine
from aegis.models.finding import Severity

DOCKER_READY = False
try:
    import subprocess as _sp
    DOCKER_READY = _sp.run(
        ["docker", "info", "--format", "ok"],
        capture_output=True, text=True, timeout=10,
    ).returncode == 0
except Exception:
    pass


# ─── فحص أمان Compose ─────────────────────────────────────────

SAFE_COMPOSE = """
services:
  app:
    image: nginx:alpine
    networks: [twin_net]
networks:
  twin_net:
    internal: true
"""

UNSAFE_NO_NET = """
services:
  app:
    image: nginx:alpine
"""

UNSAFE_PORTS = """
services:
  app:
    image: nginx:alpine
    ports: ["8080:80"]
    networks: [twin_net]
networks:
  twin_net:
    internal: true
"""


def test_validate_safe_compose(tmp_path):
    p = tmp_path / "safe.yml"
    p.write_text(SAFE_COMPOSE, encoding="utf-8")
    assert validate_compose_security(str(p)) == []


def test_validate_unsafe_no_network(tmp_path):
    p = tmp_path / "bad1.yml"
    p.write_text(UNSAFE_NO_NET, encoding="utf-8")
    violations = validate_compose_security(str(p))
    assert violations and "app" in violations[0]


def test_validate_unsafe_ports(tmp_path):
    p = tmp_path / "bad2.yml"
    p.write_text(UNSAFE_PORTS, encoding="utf-8")
    assert any("ports" in v for v in validate_compose_security(str(p)))


# ─── بوابات السلامة (بدون Docker) ─────────────────────────────

def test_exec_refused_when_not_ready():
    twin = DigitalTwin(TwinConfig(name="unit_gate"))
    with pytest.raises(SafetyViolationError):
        twin.exec_in_sandbox("sandbox", ["echo", "hi"])


def test_exec_refused_after_kill_switch():
    twin = DigitalTwin(TwinConfig(name="unit_kill"))
    twin.state = TwinState.READY          # تجاوز يدوي لأغراض الاختبار
    twin.isolation_verified = True
    twin.abort()
    with pytest.raises(SafetyViolationError):
        twin.exec_in_sandbox("sandbox", ["echo", "hi"])


# ─── وحدة اختبار وهمية + Verifier ─────────────────────────────

class FakeModule(BaseTestModule):
    name = "fake"
    vuln_type = "injection"
    target_service = "sandbox"

    def __init__(self, twin, check_result=True):
        super().__init__(twin)
        self.check_result = check_result

    def check_vulnerability(self) -> bool:
        return self.check_result

    def _run_test(self) -> TestResult:
        return TestResult(success=True, proof="fake-proof",
                          risk_level=Severity.MEDIUM)


class DummySafeTwin(DigitalTwin):
    """توأم شكلي للوحدات — لا أوامر نظام إطلاقاً."""

    def __init__(self):
        super().__init__(TwinConfig(name="dummy"))
        self.state = TwinState.READY
        self.isolation_verified = True


def test_module_runs_and_verifies():
    m = FakeModule(DummySafeTwin(), check_result=True)
    r = m.execute()
    assert r.success and r.verified


def test_module_refuses_when_twin_not_ready():
    t = DigitalTwin(TwinConfig(name="notready"))   # IDLE
    r = FakeModule(t).execute()
    assert not r.success and "غير جاهز" in r.proof


def test_verification_engine_requires_all_confirmations():
    flaky_calls = {"n": 0}

    class Flaky(FakeModule):
        def check_vulnerability(self):
            flaky_calls["n"] += 1
            return flaky_calls["n"] <= 1   # نجاح أول مرة فقط

    engine = VerificationEngine(required_confirmations=2)
    original = TestResult(success=True, proof="x")
    assert engine.verify(Flaky(DummySafeTwin()), original) is False


# ─── تكامل Docker حقيقي (يتفعل تلقائياً عند الجهوز) ────────────

@pytest.mark.skipif(not DOCKER_READY, reason="Docker engine غير جاهز")
def test_full_twin_lifecycle_isolated(tmp_path):
    twin = DigitalTwin(TwinConfig(
        name="itest", sandbox_dir=str(tmp_path / "sb"),
    ))
    try:
        assert twin.build() is True
        assert twin.is_safe_to_test

        # تنفيذ داخل الحاوية يعمل
        r = twin.exec_in_sandbox("sandbox", ["sh", "-c", "echo INSIDE_OK"])
        assert r["success"] and "INSIDE_OK" in r["stdout"]
    finally:
        twin.destroy()

    assert twin.state == TwinState.DESTROYED
