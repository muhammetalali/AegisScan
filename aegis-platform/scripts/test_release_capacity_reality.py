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
        {"return_code": 0, "external_e2e_pass": True, "kali_provider_proven": True},
        {"return_code": 0, "external_e2e_pass": True, "kali_provider_proven": True},
        {"return_code": 0, "external_e2e_pass": True, "kali_provider_proven": True},
    ]
    report = capacity.build_report(
        source_sha="a" * 40,
        tenant_results=tenants,
        samples=_samples(),
        max_running_tenants=3,
        recovery={"post_recovery_e2e_pass": True, "kali_provider_proven": True},
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
        {"return_code": 0, "external_e2e_pass": True, "kali_provider_proven": True},
        {"return_code": 0, "external_e2e_pass": True, "kali_provider_proven": True},
        {"return_code": 0, "external_e2e_pass": True, "kali_provider_proven": True},
    ]
    report = capacity.build_report(
        source_sha="b" * 40,
        tenant_results=tenants,
        samples=_samples(),
        max_running_tenants=1,
        recovery={"post_recovery_e2e_pass": False, "kali_provider_proven": False},
        minimum_tenants=3,
        minimum_postgres_connections=2,
    )
    assert report["passed"] is False
    assert report["proof"]["kali_scanner_concurrency_exercised"] is False
    assert report["proof"]["controlled_recovery"] is False


def test_tenant_environment_replaces_stale_identity_with_governed_fixture(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_E2E_EMAIL", "stale@example.test")
    monkeypatch.setenv("AEGIS_E2E_PASSWORD", "stale-secret")
    monkeypatch.setenv("AEGIS_E2E_APPROVER_EMAIL", "stale-approver@example.test")
    monkeypatch.setenv("AEGIS_E2E_APPROVER_PASSWORD", "stale-secret-2")
    fixture = {
        "AEGIS_E2E_EMAIL": "capacity@example.test",
        "AEGIS_E2E_PASSWORD": "fixture-secret",
        "AEGIS_E2E_APPROVER_EMAIL": "capacity-approver@example.test",
        "AEGIS_E2E_APPROVER_PASSWORD": "fixture-approver-secret",
    }
    env = capacity._tenant_environment(7, state_root=tmp_path, fixture=fixture)
    for key, value in fixture.items():
        assert env[key] == value
    assert env["AEGIS_E2E_EMAIL"] != "stale@example.test"
    assert env["AEGIS_E2E_STATE_PATH"].endswith("tenant-7.json")
    assert env["AEGIS_E2E_CAPACITY_MODE"] == "true"
    assert "AEGIS_E2E_GOV_ORG_ID" not in env
    assert "AEGIS_E2E_APPROVER_MEMBERSHIP_ID" not in env
