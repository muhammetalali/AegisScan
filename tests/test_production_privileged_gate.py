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
    monkeypatch.setattr(gate, "_release_deployer", lambda sha, origin: calls.append(("candidate", sha, origin)))

    release = "b" * 40
    gate.deploy(release, "https://10.20.30.40")

    assert calls[0] == ("prepare", release)
    reality = calls[1]
    deploy = calls[2]
    assert reality[1] == "production_host_reality.py"
    assert str(gate.ENV_FILE) in reality[2]
    assert deploy == ("candidate", release, "https://10.20.30.40")
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


def test_cleanup_e2e_scope_requires_exact_release_and_fixed_cleanup_contract(monkeypatch):
    monkeypatch.setattr(gate, "_assert_private_material", lambda: None)
    monkeypatch.setattr(gate, "_assert_secure_tree", lambda: None)
    monkeypatch.setattr(gate, "_git", lambda *args, **kwargs: SimpleNamespace(stdout="e" * 40 + "\n"))
    calls = []
    monkeypatch.setattr(
        gate,
        "_python",
        lambda script, *args, timeout: calls.append((script, args, timeout)),
    )

    gate.cleanup_e2e_scope("e" * 40)
    assert calls[0][0] == "production_operational_acceptance.py"
    assert "--cleanup-e2e-scope" in calls[0][1]
    assert "--release-sha" in calls[0][1]

    monkeypatch.setattr(gate, "_git", lambda *args, **kwargs: SimpleNamespace(stdout="f" * 40 + "\n"))
    with pytest.raises(gate.PrivilegedGateError, match="cleanup release SHA"):
        gate.cleanup_e2e_scope("e" * 40)


def test_gate_installation_and_sudo_caller_contract(monkeypatch):
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", gate.EXPECTED_SUDO_USER)
    gate._assert_invocation_identity()

    monkeypatch.setenv("SUDO_USER", "unexpected")
    with pytest.raises(gate.PrivilegedGateError, match="rejected sudo caller"):
        gate._assert_invocation_identity()


def test_host_bootstrap_installs_current_gate_and_sudo_boundary():
    bootstrap = (ROOT / "aegis-platform/scripts/production_host_bootstrap.sh").read_text(encoding="utf-8")
    assert 'DEPLOY_USER="aegisdeploy"' in bootstrap
    assert "useradd --create-home --user-group --shell /bin/bash" in bootstrap
    assert "production_privileged_gate.py" in bootstrap
    assert "/usr/local/sbin/aegisscan-production-gate" in bootstrap
    assert "/etc/sudoers.d/aegisscan-production-gate" in bootstrap
    assert "NOPASSWD: /usr/local/sbin/aegisscan-production-gate" in bootstrap
    assert "visudo -cf /etc/sudoers.d/aegisscan-production-gate" in bootstrap
    assert "cleanup-e2e-scope" in bootstrap
    assert "authorized_keys" in bootstrap


def test_candidate_orchestrator_executes_verified_source_without_checking_out(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    calls = []
    def git(*args, **kw):
        calls.append(args)
        return SimpleNamespace(stdout="from pathlib import Path\nPath(__file__).parents[2].joinpath('candidate-ran').write_text(__file__)\n")
    monkeypatch.setattr(gate, "_git", git)
    original_run = gate._run
    monkeypatch.setattr(gate, "_run", lambda argv, **kw: original_run(argv, cwd=tmp_path, **kw))
    gate._release_deployer("b" * 40, "https://security.internal")
    assert (tmp_path / "candidate-ran").read_text() == str(tmp_path / "aegis-platform/scripts/production_host_deploy.py")
    assert calls == [("show", "b" * 40 + ":aegis-platform/scripts/production_host_deploy.py")]


@pytest.mark.parametrize("action", ["backup", "recover-services"])
def test_resilience_actions_require_exact_checkout_and_fixed_host_script(monkeypatch, action):
    for name in ("_assert_private_material", "_assert_secure_tree", "_assert_expected_remote"):
        monkeypatch.setattr(gate, name, lambda: None)
    monkeypatch.setattr(gate, "_git", lambda *args, **kw: SimpleNamespace(stdout="" if args[0] == "status" else "a" * 40))
    calls = []
    monkeypatch.setattr(gate, "_python", lambda *args, **kw: calls.append(args))
    gate.resilience("a" * 40, action, "https://security.internal")
    assert calls[0][0] == "production_host_resilience.py"
    assert action in calls[0]
    calls.clear()
    with pytest.raises(gate.PrivilegedGateError, match="resilience release SHA"):
        gate.resilience("b" * 40, action, "https://security.internal")
    assert not calls
