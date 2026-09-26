from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "aegis_release_capacity_reality",
    Path(__file__).with_name("release_capacity_reality.py"),
)
assert _SPEC and _SPEC.loader
capacity = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = capacity
_SPEC.loader.exec_module(capacity)


def _samples(pg: int = 4):
    return [
        {
            "postgres_connections": pg,
            "celery_queue_depths": {"default": 0, "scanners": 2, "browser": 0},
        },
        {
            "postgres_connections": pg + 1,
            "celery_queue_depths": {"default": 1, "scanners": 0, "browser": 0},
        },
    ]


def test_build_report_requires_real_multi_tenant_database_broker_and_recovery_proof():
    tenants = [
        {"return_code": 0, "external_e2e_pass": True},
        {"return_code": 0, "external_e2e_pass": True},
        {"return_code": 0, "external_e2e_pass": True},
    ]
    report = capacity.build_report(
        source_sha="a" * 40,
        tenant_results=tenants,
        samples=_samples(),
        max_running_tenants=3,
        recovery={"post_recovery_e2e_pass": True},
        minimum_tenants=3,
        minimum_postgres_connections=2,
    )
    assert report["passed"] is True
    assert report["proof"]["multi_tenant_e2e"] is True
    assert report["proof"]["kali_scanner_concurrency_exercised"] is True
    assert report["proof"]["max_postgres_connections"] == 5
    assert report["proof"]["max_queue_depths"]["scanners"] == 2
    assert report["proof"]["controlled_recovery"] is True


def test_build_report_fails_closed_when_concurrency_or_recovery_is_missing():
    tenants = [
        {"return_code": 0, "external_e2e_pass": True},
        {"return_code": 0, "external_e2e_pass": True},
        {"return_code": 0, "external_e2e_pass": True},
    ]
    report = capacity.build_report(
        source_sha="b" * 40,
        tenant_results=tenants,
        samples=_samples(),
        max_running_tenants=1,
        recovery={"post_recovery_e2e_pass": False},
        minimum_tenants=3,
        minimum_postgres_connections=2,
    )
    assert report["passed"] is False
    assert report["proof"]["kali_scanner_concurrency_exercised"] is False
    assert report["proof"]["controlled_recovery"] is False


def test_tenant_environment_removes_fixed_fixture_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_E2E_EMAIL", "fixed@example.test")
    monkeypatch.setenv("AEGIS_E2E_PASSWORD", "secret")
    monkeypatch.setenv("AEGIS_E2E_APPROVER_EMAIL", "approver@example.test")
    monkeypatch.setenv("AEGIS_E2E_APPROVER_PASSWORD", "secret-2")
    env = capacity._tenant_environment(7, state_root=tmp_path)
    for key in capacity.EPHEMERAL_IDENTITY_KEYS:
        assert key not in env
    assert env["AEGIS_E2E_STATE_PATH"].endswith("tenant-7.json")
