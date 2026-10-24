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
    monkeypatch.setenv("AEGIS_E2E_ACCESS_TOKEN", "stale.actor.token")
    monkeypatch.setenv("AEGIS_E2E_APPROVER_ACCESS_TOKEN", "stale.approver.token")
    fixture = {
        "AEGIS_E2E_EMAIL": "capacity@example.test",
        "AEGIS_E2E_PASSWORD": "fixture-secret",
        "AEGIS_E2E_APPROVER_EMAIL": "capacity-approver@example.test",
        "AEGIS_E2E_APPROVER_PASSWORD": "fixture-approver-secret",
        "AEGIS_E2E_ACCESS_TOKEN": "fixture.actor.token",
        "AEGIS_E2E_APPROVER_ACCESS_TOKEN": "fixture.approver.token",
    }
    env = capacity._tenant_environment(7, state_root=tmp_path, fixture=fixture)
    for key, value in fixture.items():
        assert env[key] == value
    assert env["AEGIS_E2E_EMAIL"] != "stale@example.test"
    assert env["AEGIS_E2E_STATE_PATH"].endswith("tenant-7.json")
    assert env["AEGIS_E2E_CAPACITY_MODE"] == "true"
    assert "AEGIS_E2E_GOV_ORG_ID" not in env
    assert "AEGIS_E2E_APPROVER_MEMBERSHIP_ID" not in env



def test_parse_fixture_authorization_requires_two_real_jwt_shapes():
    parsed = capacity._parse_fixture_authorization(
        'noise\nCAPACITY_FIXTURE_READY={"actor_access":"aaa.bbb.ccc","approver_access":"ddd.eee.fff"}\n'
    )
    assert parsed == {
        "AEGIS_E2E_ACCESS_TOKEN": "aaa.bbb.ccc",
        "AEGIS_E2E_APPROVER_ACCESS_TOKEN": "ddd.eee.fff",
    }


def test_parse_fixture_authorization_fails_closed_on_missing_or_malformed_tokens():
    for output in (
        "",
        "CAPACITY_FIXTURE_READY={}",
        'CAPACITY_FIXTURE_READY={"actor_access":"not-a-jwt","approver_access":"ddd.eee.fff"}',
    ):
        try:
            capacity._parse_fixture_authorization(output)
        except capacity.CapacityRealityError:
            pass
        else:
            raise AssertionError(f"malformed fixture authorization was accepted: {output!r}")


def test_capacity_black_box_uses_preprovisioned_jwt_and_preserves_normal_login_path():
    text = (Path(__file__).parents[1] / "e2e" / "external_black_box_e2e.py").read_text(encoding="utf-8")
    assert "AEGIS_E2E_ACCESS_TOKEN" in text
    assert "AEGIS_E2E_APPROVER_ACCESS_TOKEN" in text
    assert "CAPACITY_ACTOR_AUTH=PREPROVISIONED_JWT" in text
    assert "CAPACITY_APPROVER_AUTH=PREPROVISIONED_JWT" in text
    assert "Governance approver login" in text
    assert "f'{DJANGO_URL}/auth/login/'" in text


def test_reused_governed_assessment_launcher_decision_has_exact_target_and_lineage():
    """Repeated protected deploys reuse durable approval instead of failing E2E."""
    import importlib.util
    from uuid import uuid4

    import pytest

    script = Path(__file__).parents[1] / "e2e" / "external_black_box_e2e.py"
    spec = importlib.util.spec_from_file_location("aegis_external_black_box_reuse_contract", script)
    assert spec and spec.loader
    harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(harness)
    target = "http://172.20.0.11"
    identifier = str(uuid4())
    valid = {
        "state": "authorized", "source": "existing-governed-decision",
        "id": identifier, "target": target, "authorized": True, "request": None,
    }
    allowed = {"existing-governed-decision", "single-operator-lab"}
    assert harness.require_durable_launcher_decision(valid, target, allowed) == identifier
    fresh = dict(valid, source="single-operator-lab")
    assert harness.require_durable_launcher_decision(fresh, target, allowed) == identifier
    for invalid in (
        dict(valid, target="http://other-host.invalid"),
        dict(valid, authorized=False),
        dict(valid, state="pending"),
        dict(valid, request={"request_id": "unexpected"}),
        dict(valid, source="unreviewed-source"),
        dict(valid, id="not-a-uuid"),
    ):
        with pytest.raises(RuntimeError):
            harness.require_durable_launcher_decision(invalid, target, allowed)


def test_capacity_fixture_uses_versioned_tokens_for_both_actors(monkeypatch, tmp_path):
    """Provision the existing governed fixtures with the real session generation contract."""
    import subprocess

    captured_scripts = []

    def fake_compose(compose_root, *args, **kwargs):
        assert args == ("exec", "-T", "django", "python", "manage.py", "shell")
        captured_scripts.append(kwargs["input_text"])
        return subprocess.CompletedProcess(
            args,
            0,
            'CAPACITY_FIXTURE_READY={"actor_access":"aaa.bbb.ccc","approver_access":"ddd.eee.fff"}\n',
            "",
        )

    monkeypatch.setattr(capacity, "_compose", fake_compose)
    fixture = capacity.provision_tenant_fixture(tmp_path, 7)
    assert fixture["AEGIS_E2E_ACCESS_TOKEN"] == "aaa.bbb.ccc"
    assert fixture["AEGIS_E2E_APPROVER_ACCESS_TOKEN"] == "ddd.eee.fff"
    assert len(captured_scripts) == 1
    script = captured_scripts[0]
    assert "from django_project.users.auth_views import VersionedTokenObtainPairSerializer" in script
    assert script.count("VersionedTokenObtainPairSerializer.get_token(") == 2
    assert "RefreshToken.for_user(" not in script
    compile(script, "<isolated-capacity-fixture>", "exec")
