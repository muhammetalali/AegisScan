from __future__ import annotations

from pathlib import Path
import runpy

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = ROOT / "aegis-platform" / "docker-compose.yml"
ENTRYPOINT = ROOT / "aegis-platform" / "backend" / "scanner-worker-entrypoint.sh"
DOCKERFILE = ROOT / "aegis-platform" / "backend" / "Dockerfile.django"
CELERY_APP = ROOT / "aegis-platform" / "backend" / "fastapi_app" / "celery_app.py"
WORKFLOW = ROOT / ".github" / "workflows" / "raw-l2-worker-reality.yml"


def _compose() -> dict:
    return yaml.safe_load(BASE_COMPOSE.read_text(encoding="utf-8"))


def test_compose_separates_raw_worker_from_network_administration() -> None:
    services = _compose()["services"]
    scanner = services["scanner_worker"]
    browser = services["browser_worker"]
    general = services["celery_worker"]
    egress = services["scanner_egress"]

    assert scanner["user"] == "0:0"
    assert scanner["network_mode"] == "service:scanner_egress"
    assert scanner["cap_drop"] == ["ALL"]
    assert set(scanner["cap_add"]) == {"NET_RAW", "SETUID", "SETGID", "SETPCAP"}
    assert "NET_ADMIN" not in scanner["cap_add"]
    # no_new_privs is deliberately applied only after the bounded root->aegis
    # capability handoff; applying it at container start would constrain that bootstrap.
    assert "no-new-privileges:true" not in (scanner.get("security_opt") or [])
    assert "scanner-worker-entrypoint.sh" in scanner["command"]

    assert general["cap_drop"] == ["ALL"]
    assert not general.get("cap_add")
    assert general["security_opt"] == ["no-new-privileges:true"]
    assert "-Q default" in general["command"]

    assert browser["user"] == "10001:10001"
    assert browser["network_mode"] == "service:scanner_egress"
    assert browser["cap_drop"] == ["ALL"]
    assert not browser.get("cap_add")
    assert browser["security_opt"] == ["no-new-privileges:true"]
    assert "-Q browser" in browser["command"]

    assert egress["cap_drop"] == ["ALL"]
    assert egress["cap_add"] == ["NET_ADMIN"]
    assert egress["security_opt"] == ["no-new-privileges:true"]
    assert egress["read_only"] is True

    for name in ("scanner_worker", "browser_worker", "celery_worker", "scanner_egress"):
        for volume in services[name].get("volumes", []):
            assert "/var/run/docker.sock" not in str(volume)
            assert "/run/docker.sock" not in str(volume)


def test_scanner_entrypoint_locks_privileges_after_capability_handoff() -> None:
    text = ENTRYPOINT.read_text(encoding="utf-8")
    executable = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    ).lower()

    assert "--keep=1" in executable
    assert "--user=aegis" in executable
    assert "--inh=cap_net_raw" in executable
    assert "--addamb=cap_net_raw" in executable
    assert "--drop=cap_setuid,cap_setgid,cap_setpcap" in executable
    assert "--caps=cap_net_raw+eip" in executable
    assert "setpriv --no-new-privs -- celery" in executable
    assert executable.index("--drop=cap_setuid,cap_setgid,cap_setpcap") < executable.index("setpriv --no-new-privs")
    assert "cap_net_admin" not in executable
    assert "-q scanners" in executable


def test_scanner_image_guarantees_setpriv_runtime_dependency() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "util-linux" in text
    assert "command -v setpriv >/dev/null" in text


def test_raw_scanner_tasks_are_routed_away_from_default_worker() -> None:
    text = CELERY_APP.read_text(encoding="utf-8")
    assert 'SCANNER_QUEUE = "scanners"' in text
    assert 'BROWSER_QUEUE = "browser"' in text
    assert 'task_default_queue="default"' in text
    for task in (
        "fastapi_app.tasks.security_scan.run_nmap_scan",
        "fastapi_app.tasks.advanced_scans.run_masscan_scan",
        "fastapi_app.tasks.native_capabilities.run_native_capability_scan",
        "fastapi_app.tasks.finding_validation.validate_finding_e2e",
        "fastapi_app.tasks.nmap_finding_validation.validate_nmap_finding_e2e",
        "fastapi_app.tasks.offensive_validation_tasks.validate_offensive_finding",
    ):
        assert f'"{task}": {{"queue": SCANNER_QUEUE}}' in text


def test_raw_l2_reality_workflow_keeps_runtime_proofs() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["raw-l2-worker-reality"]
    names = {step.get("name") for step in job["steps"]}
    assert {
        "Validate static Raw/L2 isolation contract",
        "Validate development and production compose boundaries",
        "Verify exact runtime identities capabilities and no-new-privileges",
        "Prove scanner namespace cannot gain NET_ADMIN",
        "Prove kernel egress policy covers raw packet scans",
        "Run real authorized scanner engine E2E",
        "Verify scanner queue exclusivity",
    } <= names


VERIFY_BLOCKED = runpy.run_path(
    str(ROOT / "aegis-platform" / "e2e" / "raw_l2_egress_proof.py")
)["verify_blocked"]
BEFORE = 'ip daddr 172.16.0.0/12 counter packets 2 bytes 120 drop'
AFTER = 'ip daddr 172.16.0.0/12 counter packets 3 bytes 180 drop'


@pytest.mark.parametrize("raw", ["", " \n", "[]", "[\n]\n"])
def test_zero_discoveries_require_real_kernel_drop(raw: str) -> None:
    VERIFY_BLOCKED(raw, BEFORE, AFTER, "172.18.0.4")


@pytest.mark.parametrize("raw", [
    "[", "not json", "null", "{}", "false",
    '[{"ip":"172.18.0.4","ports":[{"port":80}]}]',
])
def test_malformed_or_nonempty_scan_cannot_pass(raw: str) -> None:
    with pytest.raises(ValueError):
        VERIFY_BLOCKED(raw, BEFORE, AFTER, "172.18.0.4")


@pytest.mark.parametrize("before,after,target", [
    (BEFORE, BEFORE, "172.18.0.4"),
    (AFTER, BEFORE, "172.18.0.4"),
    (BEFORE, AFTER, "10.0.0.4"),
    (BEFORE, "", "172.18.0.4"),
    (BEFORE, BEFORE + '\nip daddr 10.0.0.0/8 counter packets 9 bytes 540 drop', "172.18.0.4"),
])
def test_missing_reset_or_unrelated_drop_cannot_pass(before, after, target) -> None:
    with pytest.raises(ValueError):
        VERIFY_BLOCKED("", before, after, target)
