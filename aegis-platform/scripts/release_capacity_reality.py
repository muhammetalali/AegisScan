#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "aegisscan.release-capacity-reality.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
QUEUES = ("default", "scanners", "browser")
EPHEMERAL_IDENTITY_KEYS = (
    "AEGIS_E2E_EMAIL",
    "AEGIS_E2E_PASSWORD",
    "AEGIS_E2E_APPROVER_EMAIL",
    "AEGIS_E2E_APPROVER_PASSWORD",
    "AEGIS_E2E_GOV_ORG_ID",
    "AEGIS_E2E_APPROVER_MEMBERSHIP_ID",
    "AEGIS_E2E_EPHEMERAL_FIXTURE",
    "AEGIS_E2E_CLEANUP_ONLY",
)


class CapacityRealityError(RuntimeError):
    pass


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 30,
    check: bool = True,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            check=check,
            text=True,
            capture_output=True,
            timeout=timeout,
            input=input_text,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()[-2000:]
        raise CapacityRealityError(f"command failed: {argv!r}: {detail or exc}") from exc


def _compose(
    compose_root: Path,
    *args: str,
    timeout: float = 30,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.ci.yml", "-f", "docker-compose.nmap-default-kali.yml", *args],
        cwd=compose_root,
        timeout=timeout,
        input_text=input_text,
    )


def _http_ok(url: str, timeout: float = 5) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= int(response.status) < 300
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


def wait_ready(base_url: str, *, timeout_seconds: float) -> float:
    started = time.monotonic()
    deadline = started + timeout_seconds
    while time.monotonic() < deadline:
        if _http_ok(f"{base_url.rstrip('/')}/ready") and _http_ok(f"{base_url.rstrip('/')}/health"):
            return round(time.monotonic() - started, 3)
        time.sleep(2)
    raise CapacityRealityError(f"platform did not recover readiness within {timeout_seconds}s")


def wait_kali_provider(compose_root: Path, *, timeout_seconds: float) -> float:
    started = time.monotonic()
    deadline = started + timeout_seconds
    probe = (
        "import json,urllib.request; "
        "d=json.load(urllib.request.urlopen('http://127.0.0.1:18766/healthz',timeout=2)); "
        "assert d.get('status')=='ok' and d.get('profile')=='network'"
    )
    last_error = ""
    while time.monotonic() < deadline:
        try:
            _compose(
                compose_root,
                "exec",
                "-T",
                "scanner_worker",
                "python",
                "-c",
                probe,
                timeout=10,
            )
            return round(time.monotonic() - started, 3)
        except CapacityRealityError as exc:
            last_error = str(exc)
            time.sleep(2)
    raise CapacityRealityError(f"Kali network provider did not recover readiness: {last_error[-1000:]}")


def _last_int(value: str, label: str) -> int:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        raise CapacityRealityError(f"{label} returned no value")
    try:
        result = int(lines[-1])
    except ValueError as exc:
        raise CapacityRealityError(f"{label} returned non-integer data: {lines[-1]!r}") from exc
    if result < 0:
        raise CapacityRealityError(f"{label} returned a negative value")
    return result


def sample_runtime(compose_root: Path, *, running_tenants: int) -> dict[str, Any]:
    postgres = _compose(
        compose_root,
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        os.getenv("POSTGRES_USER", "aegis"),
        "-d",
        os.getenv("POSTGRES_DB", "aegisdb"),
        "-Atc",
        "select count(*) from pg_stat_activity where datname=current_database();",
        timeout=15,
    )
    queue_depths: dict[str, int] = {}
    for queue in QUEUES:
        result = _compose(
            compose_root,
            "exec",
            "-T",
            "redis",
            "redis-cli",
            "--raw",
            "LLEN",
            queue,
            timeout=15,
        )
        queue_depths[queue] = _last_int(result.stdout, f"redis queue {queue}")
    return {
        "epoch_seconds": round(time.time(), 3),
        "running_tenants": int(running_tenants),
        "postgres_connections": _last_int(postgres.stdout, "postgres connection count"),
        "celery_queue_depths": queue_depths,
    }


def provision_tenant_fixture(compose_root: Path, index: int) -> dict[str, str]:
    token = secrets.token_hex(8)
    email = f"capacity-operator-{index}-{token}@aegisscan.local"
    password = "Aegis-Capacity-" + secrets.token_urlsafe(24)
    approver_email = f"capacity-approver-{index}-{token}@aegisscan.local"
    approver_password = "Aegis-Capacity-Approver-" + secrets.token_urlsafe(24)
    payload = {
        "email": email,
        "password": password,
        "approver_email": approver_email,
        "approver_password": approver_password,
    }
    encoded = {key: json.dumps(value) for key, value in payload.items()}
    script = f"""
from django.contrib.auth import get_user_model
from django_project.users.models import UserRole

User = get_user_model()

def upsert(email, password, first_name, last_name):
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={{
            "first_name": first_name,
            "last_name": last_name,
            "role": UserRole.SECURITY_MANAGER,
            "is_active": True,
            "is_verified": True,
        }},
    )
    user.first_name = first_name
    user.last_name = last_name
    user.role = UserRole.SECURITY_MANAGER
    user.is_active = True
    user.is_verified = True
    user.set_password(password)
    user.save()
    assert user.has_permission("project.create") and user.has_permission("scan.create")

upsert({encoded["email"]}, {encoded["password"]}, "Capacity", "Operator")
upsert({encoded["approver_email"]}, {encoded["approver_password"]}, "Capacity", "Approver")
print("CAPACITY_FIXTURE_READY")
"""
    result = _compose(
        compose_root,
        "exec",
        "-T",
        "django",
        "python",
        "manage.py",
        "shell",
        timeout=90,
        input_text=script,
    )
    if "CAPACITY_FIXTURE_READY" not in result.stdout:
        raise CapacityRealityError("governed actor provisioning returned no ready marker")
    return {
        "AEGIS_E2E_EMAIL": email,
        "AEGIS_E2E_PASSWORD": password,
        "AEGIS_E2E_APPROVER_EMAIL": approver_email,
        "AEGIS_E2E_APPROVER_PASSWORD": approver_password,
    }

def _tenant_environment(
    index: int,
    *,
    state_root: Path,
    fixture: dict[str, str],
) -> dict[str, str]:
    env = os.environ.copy()
    for key in EPHEMERAL_IDENTITY_KEYS:
        env.pop(key, None)
    env.update(fixture)
    env["AEGIS_E2E_STATE_PATH"] = str(state_root / f"tenant-{index}.json")
    env["AEGIS_E2E_CAPACITY_MODE"] = "true"
    return env


def launch_tenant(
    index: int,
    *,
    script: Path,
    state_root: Path,
    log_root: Path,
    fixture: dict[str, str],
) -> tuple[subprocess.Popen[str], Any, Path]:
    log_path = log_root / f"tenant-{index}.log"
    handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, str(script)],
        env=_tenant_environment(index, state_root=state_root, fixture=fixture),
        stdout=handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return process, handle, log_path


def _wait_tenants(
    *,
    script: Path,
    tenant_count: int,
    state_root: Path,
    log_root: Path,
    compose_root: Path,
    timeout_seconds: float,
    sample_interval: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    fixtures = [
        provision_tenant_fixture(compose_root, index)
        for index in range(tenant_count)
    ]
    processes = [
        launch_tenant(
            index,
            script=script,
            state_root=state_root,
            log_root=log_root,
            fixture=fixtures[index],
        )
        for index in range(tenant_count)
    ]
    samples: list[dict[str, Any]] = []
    started = time.monotonic()
    max_running = 0
    try:
        while True:
            running = sum(1 for process, _, _ in processes if process.poll() is None)
            max_running = max(max_running, running)
            samples.append(sample_runtime(compose_root, running_tenants=running))
            if running == 0:
                break
            if time.monotonic() - started > timeout_seconds:
                raise CapacityRealityError(f"multi-tenant capacity run exceeded {timeout_seconds}s")
            time.sleep(sample_interval)
    finally:
        for process, handle, _ in processes:
            if process.poll() is None:
                process.terminate()
        for process, handle, _ in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            handle.close()

    results: list[dict[str, Any]] = []
    for index, (process, _, log_path) in enumerate(processes):
        content = log_path.read_text(encoding="utf-8", errors="replace")
        state_path = state_root / f"tenant-{index}.json"
        state: dict[str, Any] = {}
        if state_path.is_file():
            try:
                loaded = json.loads(state_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    state = loaded
            except (OSError, json.JSONDecodeError):
                state = {}
        routing = state.get("provider_routing") if isinstance(state.get("provider_routing"), dict) else {}
        runtime = state.get("runtime_provenance") if isinstance(state.get("runtime_provenance"), dict) else {}
        kali_provider_proven = (
            routing.get("mode") == "default-kali"
            and routing.get("selected_provider") == "kali"
            and runtime.get("provider") == "aegis-kali-network"
            and runtime.get("profile") == "network"
        )
        results.append(
            {
                "tenant": index,
                "return_code": int(process.returncode or 0),
                "external_e2e_pass": "EXTERNAL_REAL_E2E=PASS" in content,
                "kali_provider_proven": kali_provider_proven,
                "state": str(state_path),
                "log": str(log_path),
            }
        )
    return results, samples, max_running


def prove_recovery(
    *,
    compose_root: Path,
    base_url: str,
    script: Path,
    state_root: Path,
    log_root: Path,
    readiness_timeout: float,
    e2e_timeout: float,
) -> dict[str, Any]:
    fixture = provision_tenant_fixture(compose_root, 10_000)
    _compose(
        compose_root,
        "restart",
        "fastapi",
        "celery_worker",
        "scanner_worker",
        "kali_network",
        timeout=120,
    )
    recovery_seconds = wait_ready(base_url, timeout_seconds=readiness_timeout)
    kali_recovery_seconds = wait_kali_provider(compose_root, timeout_seconds=readiness_timeout)
    running = _compose(
        compose_root,
        "ps",
        "--status",
        "running",
        "--services",
        "fastapi",
        "celery_worker",
        "scanner_worker",
        "kali_network",
        timeout=30,
    )
    services = {line.strip() for line in running.stdout.splitlines() if line.strip()}
    required = {"fastapi", "celery_worker", "scanner_worker", "kali_network"}
    if not required.issubset(services):
        raise CapacityRealityError(f"recovered services missing: {sorted(required - services)}")

    process, handle, log_path = launch_tenant(
        10_000,
        script=script,
        state_root=state_root,
        log_root=log_root,
        fixture=fixture,
    )
    try:
        return_code = process.wait(timeout=e2e_timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait(timeout=10)
        raise CapacityRealityError("post-recovery scanner E2E timed out") from exc
    finally:
        handle.close()
    content = log_path.read_text(encoding="utf-8", errors="replace")
    state_path = state_root / "tenant-10000.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CapacityRealityError("post-recovery scanner state evidence is missing or invalid") from exc
    routing = state.get("provider_routing") if isinstance(state, dict) else {}
    runtime = state.get("runtime_provenance") if isinstance(state, dict) else {}
    kali_provider_proven = (
        isinstance(routing, dict)
        and isinstance(runtime, dict)
        and routing.get("mode") == "default-kali"
        and routing.get("selected_provider") == "kali"
        and runtime.get("provider") == "aegis-kali-network"
        and runtime.get("profile") == "network"
    )
    if return_code != 0 or "EXTERNAL_REAL_E2E=PASS" not in content or not kali_provider_proven:
        raise CapacityRealityError("post-recovery default-Kali scanner E2E did not pass")
    return {
        "services": sorted(services),
        "readiness_seconds": recovery_seconds,
        "kali_provider_readiness_seconds": kali_recovery_seconds,
        "post_recovery_e2e_pass": True,
        "kali_provider_proven": True,
        "state": str(state_path),
        "log": str(log_path),
    }


def build_report(
    *,
    source_sha: str,
    tenant_results: list[dict[str, Any]],
    samples: list[dict[str, Any]],
    max_running_tenants: int,
    recovery: dict[str, Any],
    minimum_tenants: int,
    minimum_postgres_connections: int,
) -> dict[str, Any]:
    max_pg = max((int(sample["postgres_connections"]) for sample in samples), default=0)
    queue_max = {
        queue: max(
            (int((sample.get("celery_queue_depths") or {}).get(queue, 0)) for sample in samples),
            default=0,
        )
        for queue in QUEUES
    }
    tenant_pass = (
        len(tenant_results) >= minimum_tenants
        and all(item.get("return_code") == 0 and item.get("external_e2e_pass") is True and item.get("kali_provider_proven") is True for item in tenant_results)
    )
    concurrency_pass = max_running_tenants >= minimum_tenants
    postgres_pass = max_pg >= minimum_postgres_connections
    broker_observed = bool(samples) and all(
        set((sample.get("celery_queue_depths") or {}).keys()) == set(QUEUES)
        for sample in samples
    )
    recovery_pass = recovery.get("post_recovery_e2e_pass") is True and recovery.get("kali_provider_proven") is True
    passed = all((tenant_pass, concurrency_pass, postgres_pass, broker_observed, recovery_pass))
    return {
        "schema": SCHEMA,
        "source_sha": source_sha,
        "passed": passed,
        "proof": {
            "multi_tenant_e2e": tenant_pass,
            "max_concurrent_tenants": max_running_tenants,
            "postgres_concurrent_activity_observed": postgres_pass,
            "max_postgres_connections": max_pg,
            "celery_broker_observed": broker_observed,
            "max_queue_depths": queue_max,
            "kali_scanner_concurrency_exercised": tenant_pass and concurrency_pass,
            "controlled_recovery": recovery_pass,
        },
        "thresholds": {
            "minimum_tenants": minimum_tenants,
            "minimum_postgres_connections": minimum_postgres_connections,
        },
        "tenant_results": tenant_results,
        "runtime_samples": samples,
        "recovery": recovery,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AegisScan integrated release capacity/recovery reality proof")
    parser.add_argument("--compose-root", type=Path, default=Path("aegis-platform"))
    parser.add_argument("--e2e-script", type=Path, default=Path("aegis-platform/e2e/external_black_box_e2e.py"))
    parser.add_argument("--base-url", default="http://localhost")
    parser.add_argument("--tenants", type=int, default=3)
    parser.add_argument("--tenant-timeout-seconds", type=float, default=900)
    parser.add_argument("--sample-interval-seconds", type=float, default=2)
    parser.add_argument("--readiness-timeout-seconds", type=float, default=180)
    parser.add_argument("--minimum-postgres-connections", type=int, default=2)
    parser.add_argument("--output", type=Path, default=Path("release-capacity-reality.json"))
    parser.add_argument("--evidence-dir", type=Path, default=Path("capacity-evidence"))
    args = parser.parse_args()
    if not 2 <= args.tenants <= 16:
        parser.error("--tenants must be between 2 and 16")
    if not 0.5 <= args.sample_interval_seconds <= 30:
        parser.error("--sample-interval-seconds must be between 0.5 and 30")
    if not 60 <= args.tenant_timeout_seconds <= 3600:
        parser.error("--tenant-timeout-seconds must be between 60 and 3600")
    if not 1 <= args.minimum_postgres_connections <= 1000:
        parser.error("--minimum-postgres-connections must be between 1 and 1000")
    return args


def main() -> int:
    args = parse_args()
    compose_root = args.compose_root.resolve()
    e2e_script = args.e2e_script.resolve()
    if not compose_root.is_dir() or not e2e_script.is_file():
        raise SystemExit("compose root or E2E script is missing")

    evidence_dir = args.evidence_dir.resolve()
    state_root = evidence_dir / "state"
    log_root = evidence_dir / "logs"
    state_root.mkdir(parents=True, exist_ok=True)
    log_root.mkdir(parents=True, exist_ok=True)

    source_sha = os.getenv("AEGIS_EXACT_HEAD", os.getenv("GITHUB_SHA", "")).strip().lower()
    if not SHA_RE.fullmatch(source_sha):
        raise SystemExit("exact source SHA must be 40 lowercase hexadecimal characters")
    tenant_results, samples, max_running = _wait_tenants(
        script=e2e_script,
        tenant_count=args.tenants,
        state_root=state_root,
        log_root=log_root,
        compose_root=compose_root,
        timeout_seconds=args.tenant_timeout_seconds,
        sample_interval=args.sample_interval_seconds,
    )
    recovery = prove_recovery(
        compose_root=compose_root,
        base_url=args.base_url,
        script=e2e_script,
        state_root=state_root,
        log_root=log_root,
        readiness_timeout=args.readiness_timeout_seconds,
        e2e_timeout=args.tenant_timeout_seconds,
    )
    report = build_report(
        source_sha=source_sha,
        tenant_results=tenant_results,
        samples=samples,
        max_running_tenants=max_running,
        recovery=recovery,
        minimum_tenants=args.tenants,
        minimum_postgres_connections=args.minimum_postgres_connections,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
