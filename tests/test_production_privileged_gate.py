import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_privileged_gate.py"
SPEC = importlib.util.spec_from_file_location("production_privileged_gate", PATH)
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def test_release_and_origin_validation_are_fail_closed():
    assert gate._release_sha("a" * 40) == "a" * 40
    with pytest.raises(gate.PrivilegedGateError, match="40 lowercase"):
        gate._release_sha("main")

    assert gate._origin("https://10.20.30.40") == "https://10.20.30.40"
    assert gate._origin("https://security.internal:8443") == "https://security.internal:8443"
    for value in (
        "http://10.20.30.40",
        "https://127.0.0.1",
        "https://203.0.113.10",
        "https://user:pass@security.internal",
        "https://security.internal/path",
    ):
        with pytest.raises(gate.PrivilegedGateError):
            gate._origin(value)


def test_git_invocation_disables_hooks_and_local_file_protocol(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(stdout="ok\n")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    result = gate._git("status", "--porcelain")
    assert result.stdout == "ok\n"
    argv = captured["argv"]
    assert argv[0] == "/usr/bin/git"
    assert "core.hooksPath=/dev/null" in argv
    assert "protocol.file.allow=never" in argv
    assert captured["kwargs"]["env"]["GIT_CONFIG_NOSYSTEM"] == "1"


def test_deploy_uses_only_fixed_root_owned_contract_paths(monkeypatch):
    calls = []
    monkeypatch.setattr(gate, "_assert_private_material", lambda: None)
    monkeypatch.setattr(gate, "_prepare_release", lambda release: calls.append(("prepare", release)))
    monkeypatch.setattr(gate, "_assert_secure_tree", lambda: calls.append(("secure",)))
    monkeypatch.setattr(
        gate,
        "_python",
        lambda script, *args, timeout: calls.append(("python", script, args, timeout)),
    )

    release = "b" * 40
    gate.deploy(release, "https://10.20.30.40")

    assert calls[0] == ("prepare", release)
    reality = calls[1]
    deploy = calls[2]
    assert reality[1] == "production_host_reality.py"
    assert str(gate.ENV_FILE) in reality[2]
    assert deploy[1] == "production_host_deploy.py"
    assert "--release-sha" in deploy[2]
    assert release in deploy[2]
    assert "--origin" in deploy[2]
    assert "https://10.20.30.40" in deploy[2]
    assert calls[-1] == ("secure",)


def test_accept_requires_exact_release_before_root_operational_acceptance(monkeypatch):
    monkeypatch.setattr(gate, "_assert_private_material", lambda: None)
    monkeypatch.setattr(gate, "_assert_secure_tree", lambda: None)
    monkeypatch.setattr(gate, "_git", lambda *args, **kwargs: SimpleNamespace(stdout="c" * 40 + "\n"))
    calls = []
    monkeypatch.setattr(
        gate,
        "_python",
        lambda script, *args, timeout: calls.append((script, args, timeout)),
    )

    gate.accept("c" * 40)
    assert calls[0][0] == "production_operational_acceptance.py"
    assert "--release-sha" in calls[0][1]

    monkeypatch.setattr(gate, "_git", lambda *args, **kwargs: SimpleNamespace(stdout="d" * 40 + "\n"))
    with pytest.raises(gate.PrivilegedGateError, match="checkout does not match"):
        gate.accept("c" * 40)


def test_gate_installation_and_sudo_caller_contract(monkeypatch):
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", gate.EXPECTED_SUDO_USER)
    gate._assert_invocation_identity()

    monkeypatch.setenv("SUDO_USER", "unexpected")
    with pytest.raises(gate.PrivilegedGateError, match="rejected sudo caller"):
        gate._assert_invocation_identity()
