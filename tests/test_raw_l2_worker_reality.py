from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = ROOT / "aegis-platform" / "docker-compose.yml"
ENTRYPOINT = ROOT / "aegis-platform" / "backend" / "scanner-worker-entrypoint.sh"
CELERY_APP = ROOT / "aegis-platform" / "backend" / "fastapi_app" / "celery_app.py"
WORKFLOW = ROOT / ".github" / "workflows" / "raw-l2-worker-reality.yml"


def _compose() -> dict:
    return yaml.safe_load(BASE_COMPOSE.read_text(encoding="utf-8"))


def test_compose_separates_raw_worker_from_network_administration() -> None:
    services = _compose()["services"]
    scanner = services["scanner_worker"]
    general = services["celery_worker"]
    egress = services["scanner_egress"]

    assert scanner["user"] == "0:0"
    assert scanner["network_mode"] == "service:scanner_egress"
    assert scanner["cap_drop"] == ["ALL"]
    assert set(scanner["cap_add"]) == {"NET_RAW", "SETUID", "SETGID", "SETPCAP"}
    assert "NET_ADMIN" not in scanner["cap_add"]
    assert scanner["security_opt"] == ["no-new-privileges:true"]
    assert "scanner-worker-entrypoint.sh" in scanner["command"]

    assert general["cap_drop"] == ["ALL"]
    assert not general.get("cap_add")
    assert general["security_opt"] == ["no-new-privileges:true"]
    assert "-Q default" in general["command"]

    assert egress["cap_drop"] == ["ALL"]
    assert egress["cap_add"] == ["NET_ADMIN"]
    assert egress["security_opt"] == ["no-new-privileges:true"]
    assert egress["read_only"] is True

    for name in ("scanner_worker", "celery_worker", "scanner_egress"):
        for volume in services[name].get("volumes", []):
            assert "/var/run/docker.sock" not in str(volume)
            assert "/run/docker.sock" not in str(volume)


def test_scanner_entrypoint_drops_bootstrap_capabilities_before_celery() -> None:
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
    assert "cap_net_admin" not in executable
    assert "-q scanners" in executable


def test_raw_scanner_tasks_are_routed_away_from_default_worker() -> None:
    text = CELERY_APP.read_text(encoding="utf-8")
    assert 'SCANNER_QUEUE = "scanners"' in text
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
        "Run real authorized scanner engine E2E",
        "Verify scanner queue exclusivity",
    } <= names
