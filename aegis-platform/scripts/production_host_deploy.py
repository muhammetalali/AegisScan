#!/usr/bin/env python3
"""Fail-closed production host deployment orchestrator for AegisScan."""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SCRIPT_DIR = Path(__file__).resolve().parent
PLATFORM_DIR = SCRIPT_DIR.parent
REPO_ROOT = PLATFORM_DIR.parent
TRUST_BOOTSTRAP = SCRIPT_DIR / "production_execution_trust_bootstrap.py"
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
    "docker-compose.backup.yml",
)
GIB = 1024 ** 3
PRODUCTION_MINIMUM_FREE_BYTES = 60 * GIB
PRODUCTION_TARGET_FREE_BYTES = 68 * GIB
MAX_STORAGE_DIAGNOSTIC_BYTES = 16 * 1024


class DeployError(RuntimeError):
    pass


class DeploymentInterrupted(DeployError):
    pass


def _deployment_signal_handler(signum, _frame) -> None:
    try:
        name = signal.Signals(signum).name
    except ValueError:
        name = str(signum)
    raise DeploymentInterrupted(f"production deployment interrupted by {name}")


def _run(
    argv: list[str],
    *,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
    capture: bool = True,
    timeout: int = 3600,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        capture_output=capture,
        timeout=timeout,
    )


def _free_bytes(path: Path = PLATFORM_DIR) -> int:
    if not path.exists():
        raise DeployError(f"production storage path does not exist: {path}")
    return shutil.disk_usage(path).free


def _assert_storage_floor(stage: str) -> int:
    free = _free_bytes()
    if free < PRODUCTION_MINIMUM_FREE_BYTES:
        raise DeployError(
            "production free disk fell below the 60 GiB safety floor "
            f"after {stage}: {free} < {PRODUCTION_MINIMUM_FREE_BYTES}"
        )
    return free


def _docker_df() -> str:
    result = _run(["docker", "system", "df"], cwd=PLATFORM_DIR, timeout=60)
    return result.stdout.strip()[-MAX_STORAGE_DIAGNOSTIC_BYTES:]


def _storage_stage(name: str, argv: list[str]) -> dict[str, object]:
    before = _free_bytes()
    result = _run(argv, cwd=PLATFORM_DIR, timeout=1800)
    after = _free_bytes()
    return {
        "name": name,
        "argv": argv,
        "before_free_bytes": before,
        "after_free_bytes": after,
        "reclaimed_bytes": max(0, after - before),
        "stdout_tail": result.stdout.strip()[-4000:],
    }


def _post_build_storage(stage: str) -> dict[str, object]:
    """Recover build scratch space without pruning candidate or rollback images.

    Images just exported by a build have no containers yet. The general host
    reclaimer's image/container pruning is therefore unsafe at this boundary.
    Keep recent cache for resumable builds unless the measured hard floor needs
    recovery, and remeasure instead of trusting Docker's reclaimed-byte count.
    """
    before = _free_bytes()
    result: dict[str, object] = {
        "event": "production-build-storage-checkpoint",
        "schema": "aegisscan.production-post-build-storage-reclaim.v1",
        "stage": stage,
        "minimum_free_bytes": PRODUCTION_MINIMUM_FREE_BYTES,
        "before_free_bytes": before,
        "stages": [],
        "image_prune_performed": False,
        "container_prune_performed": False,
        "volume_prune_performed": False,
    }
    if before < PRODUCTION_MINIMUM_FREE_BYTES:
        result["docker_df_before"] = _docker_df()
        stages = [
            _storage_stage(
                "aged-build-cache",
                ["docker", "builder", "prune", "--all", "--force", "--filter", "until=24h"],
            )
        ]
        if _free_bytes() < PRODUCTION_MINIMUM_FREE_BYTES:
            stages.append(
                _storage_stage("all-build-cache", ["docker", "builder", "prune", "--all", "--force"])
            )
        result["stages"] = stages
        result["docker_df_after"] = _docker_df()

    after = _free_bytes()
    result["after_free_bytes"] = after
    result["reclaimed_bytes"] = max(0, after - before)
    result["remaining_deficit_bytes"] = max(0, PRODUCTION_MINIMUM_FREE_BYTES - after)
    result["status"] = "success" if after >= PRODUCTION_MINIMUM_FREE_BYTES else "insufficient-capacity"
    result["mode"] = (
        "noop-floor-preserved" if before >= PRODUCTION_MINIMUM_FREE_BYTES and after >= PRODUCTION_MINIMUM_FREE_BYTES
        else "floor-restored" if after >= PRODUCTION_MINIMUM_FREE_BYTES
        else "insufficient-cache-reclaim"
    )
    print(json.dumps(result, sort_keys=True), flush=True)
    _assert_storage_floor(stage)
    return result


def _host_storage_reclaim(
    *,
    minimum_free_bytes: int = PRODUCTION_MINIMUM_FREE_BYTES,
    target_free_bytes: int = PRODUCTION_TARGET_FREE_BYTES,
) -> dict[str, object]:
    if minimum_free_bytes <= 0:
        raise DeployError("production minimum free bytes must be positive")
    if target_free_bytes < minimum_free_bytes:
        raise DeployError("production target free bytes must be greater than or equal to the minimum")

    before = _free_bytes()
    result: dict[str, object] = {
        "schema": "aegisscan.production-host-storage-reclaim.v1",
        "status": "success",
        "minimum_free_bytes": minimum_free_bytes,
        "target_free_bytes": target_free_bytes,
        "before_free_bytes": before,
        "after_free_bytes": before,
        "reclaimed_bytes": 0,
        "stages": [],
        "volume_prune_performed": False,
    }
    if before >= target_free_bytes:
        result["mode"] = "noop-capacity-already-sufficient"
        return result

    try:
        _run(["docker", "info"], cwd=PLATFORM_DIR, timeout=60)
        result["docker_df_before"] = _docker_df()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise DeployError(f"privileged Docker storage reclaim is unavailable: {exc}") from exc

    stages = [
        ("aged-build-cache", ["docker", "builder", "prune", "--all", "--force", "--filter", "until=24h"]),
        ("aged-stopped-containers", ["docker", "container", "prune", "--force", "--filter", "until=24h"]),
        ("aged-unused-images", ["docker", "image", "prune", "--all", "--force", "--filter", "until=24h"]),
    ]
    stage_results: list[dict[str, object]] = []
    for name, argv in stages:
        stage_results.append(_storage_stage(name, argv))
        if _free_bytes() >= target_free_bytes:
            break

    if _free_bytes() < minimum_free_bytes:
        aggressive = [
            ("all-build-cache", ["docker", "builder", "prune", "--all", "--force"]),
            ("all-stopped-containers", ["docker", "container", "prune", "--force"]),
            ("all-unused-images", ["docker", "image", "prune", "--all", "--force"]),
        ]
        for name, argv in aggressive:
            stage_results.append(_storage_stage(name, argv))
            if _free_bytes() >= target_free_bytes:
                break

    after = _free_bytes()
    result["stages"] = stage_results
    result["after_free_bytes"] = after
    result["reclaimed_bytes"] = max(0, after - before)
    result["docker_df_after"] = _docker_df()
    result["mode"] = (
        "target-restored"
        if after >= target_free_bytes
        else "minimum-restored"
        if after >= minimum_free_bytes
        else "insufficient-reclaim"
    )
    if after < minimum_free_bytes:
        raise DeployError(
            "privileged bounded Docker reclaim completed without touching volumes, "
            f"but free disk is still below the production minimum: {after} < {minimum_free_bytes}"
        )
    return result


def _private_file(path: Path, *, max_bytes: int = 1024 * 1024) -> None:
    if not path.is_file():
        raise DeployError(f"required private file does not exist: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise DeployError(f"private file must be mode 0600 or stricter: {path}")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise DeployError(f"private file has invalid size: {path}")


def _load_env_file(path: Path) -> dict[str, str]:
    _private_file(path)
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise DeployError(f"invalid env assignment at line {line_number}")
        name, value = line.split("=", 1)
        name = name.strip()
        if not ENV_KEY_RE.fullmatch(name):
            raise DeployError(f"invalid env key at line {line_number}: {name!r}")
        value = value.strip()
        if value and value[0] in {'"', "'"}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise DeployError(f"unterminated quoted env value at line {line_number}")
            value = value[1:-1]
        if "\x00" in value or "\n" in value or "\r" in value:
            raise DeployError(f"control characters are not allowed in env file line {line_number}")
        values[name] = value
    return values


def _snapshot_private_env(path: Path) -> tuple[bytes, int, int]:
    _private_file(path)
    state = path.stat()
    return path.read_bytes(), state.st_uid, state.st_gid


def _restore_private_env(path: Path, snapshot: tuple[bytes, int, int]) -> None:
    data, uid, gid = snapshot
    temporary = path.with_name(f".{path.name}.rollback-{os.getpid()}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        os.chown(path, uid, gid)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _execution_profile_environment(environment: dict[str, str]) -> dict[str, str]:
    resolved = dict(environment)
    resolved["AEGIS_ENTERPRISE_CA_HOST_BUNDLE"] = "/etc/aegisscan/enterprise-ca.pem"
    mode = resolved.get("AEGIS_RECON_PROVIDER", "default-kali").strip().lower()
    try:
        canary_bps = int(resolved.get("AEGIS_KALI_RECON_CANARY_BPS", "0").strip())
    except ValueError:
        canary_bps = 0

    profiles = {
        item.strip()
        for item in resolved.get("COMPOSE_PROFILES", "").split(",")
        if item.strip()
    }
    if mode in {"default-kali", "kali"} or (mode == "canary" and canary_bps > 0):
        profiles.add("kali-recon")
    else:
        profiles.discard("kali-recon")

    if profiles:
        resolved["COMPOSE_PROFILES"] = ",".join(sorted(profiles))
    else:
        resolved.pop("COMPOSE_PROFILES", None)
    return resolved


def _rollback_execution_environment(environment: dict[str, str]) -> dict[str, str]:
    """Restore the previous policy; only unset pre-M4 fields receive legacy defaults."""
    safe = dict(environment)
    safe.setdefault("AEGIS_RECON_PROVIDER", "legacy")
    safe.setdefault("AEGIS_RECON_LEGACY_DISABLED", "false")
    safe.setdefault("AEGIS_KALI_RECON_CANARY_BPS", "0")
    return _execution_profile_environment(safe)


def _recon_rollout_state(environment: dict[str, str]) -> tuple[str, int]:
    mode = environment.get("AEGIS_RECON_PROVIDER", "default-kali").strip().lower()
    raw_bps = environment.get("AEGIS_KALI_RECON_CANARY_BPS", "0").strip()
    try:
        bps = int(raw_bps)
    except ValueError as exc:
        raise DeployError("AEGIS_KALI_RECON_CANARY_BPS must be an integer") from exc
    return mode, bps


def _validate_origin(origin: str) -> str:
    parsed = urlparse(origin.strip())
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise DeployError(
            "public origin must be an explicit HTTPS origin without credentials, path, query or fragment"
        )
    return f"https://{parsed.hostname}" + (f":{parsed.port}" if parsed.port and parsed.port != 443 else "")


def _compose(env_file: Path, *args: str) -> list[str]:
    argv = ["docker", "compose", "--env-file", str(env_file)]
    for name in COMPOSE_FILES:
        argv.extend(["-f", str(PLATFORM_DIR / name)])
    argv.extend(args)
    return argv


def _git(*args: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(
        ["git", "-c", f"safe.directory={REPO_ROOT}", *args],
        capture=capture,
        timeout=600,
    )


def _current_sha() -> str:
    return _git("rev-parse", "HEAD").stdout.strip()


def _assert_clean_repo() -> None:
    status = _git("status", "--porcelain", "--untracked-files=no").stdout.strip()
    if status:
        raise DeployError("production checkout has tracked local modifications")


def _ensure_release(release_sha: str) -> None:
    if not SHA_RE.fullmatch(release_sha):
        raise DeployError("release SHA must be exactly 40 lowercase hexadecimal characters")
    try:
        _git("cat-file", "-e", f"{release_sha}^{{commit}}")
    except subprocess.CalledProcessError:
        _git("fetch", "--no-tags", "origin", release_sha, capture=False)
        _git("cat-file", "-e", f"{release_sha}^{{commit}}")
    _git("fetch", "--no-tags", "origin", "main", capture=False)
    ancestor = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={REPO_ROOT}",
            "merge-base",
            "--is-ancestor",
            release_sha,
            "origin/main",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        raise DeployError("release SHA is not contained in origin/main")


def _migration_changes(previous_sha: str, release_sha: str) -> list[str]:
    if previous_sha == release_sha:
        return []
    output = _git("diff", "--name-only", previous_sha, release_sha, "--").stdout
    return [
        line.strip()
        for line in output.splitlines()
        if "/migrations/" in line and line.strip().endswith(".py")
    ]


def _prepare_execution_trust(env_file: Path, release_sha: str) -> dict[str, str]:
    if not TRUST_BOOTSTRAP.is_file():
        raise DeployError(f"production execution trust bootstrap is unavailable: {TRUST_BOOTSTRAP}")
    _run(
        [
            sys.executable,
            str(TRUST_BOOTSTRAP),
            "--env-file",
            str(env_file),
            "--release-sha",
            release_sha,
        ],
        cwd=REPO_ROOT,
        capture=False,
        timeout=21600,
    )
    _post_build_storage("execution-trust-bootstrap")
    return _load_env_file(env_file)


def _preflight(env_file: Path, deployment_env: dict[str, str]) -> None:
    tls_dir = PLATFORM_DIR / "docker" / "ssl"
    _run(
        [sys.executable, str(SCRIPT_DIR / "production_preflight.py"), "--tls-dir", str(tls_dir)],
        cwd=REPO_ROOT,
        env=deployment_env,
        timeout=60,
    )
    _run(_compose(env_file, "config", "--quiet"), cwd=PLATFORM_DIR, env=deployment_env, timeout=120)
    _run(["docker", "info"], capture=True, timeout=60)


def _running_services(env_file: Path, deployment_env: dict[str, str]) -> set[str]:
    result = subprocess.run(
        _compose(env_file, "ps", "--status", "running", "--services"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return set()
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def _backup_before_upgrade(env_file: Path, deployment_env: dict[str, str]) -> dict[str, str | bool]:
    running = _running_services(env_file, deployment_env)
    if "postgres" not in running:
        return {"performed": False, "reason": "first-deploy-or-postgres-not-running"}
    result = _run(
        _compose(
            env_file,
            "run",
            "--rm",
            "--no-deps",
            "backup",
            "once",
        ),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        timeout=14400,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise DeployError("remote backup returned no durable state")
    try:
        payload = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise DeployError("remote backup did not return valid state JSON") from exc
    if payload.get("status") != "success" or not payload.get("backup_id"):
        raise DeployError("remote backup did not complete successfully")
    return {
        "performed": True,
        "backup_id": str(payload["backup_id"]),
        "manifest_key": str(payload.get("manifest_key", "")),
        "manifest_version_id": str(payload.get("manifest_version_id", "")),
    }


def _build_stack(env_file: Path, deployment_env: dict[str, str]) -> dict[str, object]:
    _run(
        _compose(env_file, "build", "--pull"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        capture=False,
        timeout=7200,
    )
    storage = _post_build_storage("application-image-build")
    # Validate the gateway image and mounted TLS config before replacing services.
    _run(
        _compose(env_file, "run", "--rm", "--no-deps", "nginx", "nginx", "-t"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        capture=False,
        timeout=180,
    )
    return storage


def _deploy_stack(env_file: Path, deployment_env: dict[str, str]) -> None:
    _run(
        _compose(env_file, "up", "-d", "--no-build", "--remove-orphans"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        capture=False,
        timeout=1800,
    )
    # Git checkout replaces config inodes; a retained file bind mount can still
    # expose the old config. Recreate only the gateway after application startup.
    _run(
        _compose(env_file, "up", "-d", "--no-build", "--no-deps", "--force-recreate", "nginx"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        capture=False,
        timeout=180,
    )
    _assert_storage_floor("service-start")


def _scanner_worker_state(env_file: Path, deployment_env: dict[str, str]) -> str:
    """Collect bounded state only: never dump container config, env or raw logs."""
    try:
        result = _run(
            _compose(env_file, "ps", "--all", "--quiet", "scanner_worker"),
            cwd=PLATFORM_DIR, env=deployment_env, timeout=10,
        )
        ids = result.stdout.split()
        if not ids:
            return "no scanner_worker container"
        if len(ids) > 4 or any(not re.fullmatch(r"[0-9a-f]{12,64}", cid) for cid in ids):
            return "invalid scanner_worker container IDs"
        result = _run(
            ["docker", "inspect", "--format",
             "status={{.State.Status}} exit={{.State.ExitCode}} "
             "oom={{.State.OOMKilled}} restarting={{.State.Restarting}} "
             "restarts={{.RestartCount}}", *ids],
            cwd=PLATFORM_DIR, env=deployment_env, timeout=10,
        )
        lines = result.stdout.strip().splitlines()
        pattern = r"status=[a-z]+ exit=-?[0-9]+ oom=(true|false) restarting=(true|false) restarts=[0-9]+"
        if not lines or any(not re.fullmatch(pattern, line) for line in lines):
            return "unrecognized scanner_worker state"
        return "; ".join(lines)[:1024]
    except (OSError, subprocess.SubprocessError):
        # Diagnostics must not replace the original acceptance failure or expose
        # stderr from Docker/Compose, which may contain environment values.
        return "scanner_worker state unavailable"


def _execution_plane_acceptance(
    env_file: Path,
    deployment_env: dict[str, str],
    attempts: int = 40,
) -> None:
    mode, canary_bps = _recon_rollout_state(deployment_env)
    active_canary = mode == "canary" and canary_bps > 0
    active_kali = mode in {"default-kali", "kali"} or active_canary
    if mode == "default-kali":
        command = (
            "from fastapi_app.services.kali_recon_provider import "
            "_preflight_runtime_attestation,_trusted_expected_provenance,legacy_recon_disabled,recon_provider_decision; "
            "assert legacy_recon_disabled() is True; "
            "capabilities=('recon.fierce','recon.dnsenum','recon.subfinder','recon.amass'); "
            "decisions=[recon_provider_decision(capability) for capability in capabilities]; "
            "assert all(item.selected_provider == 'kali' for item in decisions); "
            "assert all(item.parity_approved is True for item in decisions); "
            "assert all(item.reason == 'default-kali-parity-approved' for item in decisions); "
            "_preflight_runtime_attestation(_trusted_expected_provenance())"
        )
    elif active_kali:
        command = (
            "from fastapi_app.services.kali_recon_provider import "
            "_preflight_runtime_attestation,_trusted_expected_provenance; "
            "_preflight_runtime_attestation(_trusted_expected_provenance())"
        )
    elif mode == "canary":
        command = (
            "from fastapi_app.services.kali_recon_provider import recon_provider_decision; "
            "d=recon_provider_decision('recon.fierce',routing_key='deployment-acceptance'); "
            "assert d.selected_provider == 'legacy' and d.reason == 'canary-rollback-zero'"
        )
    else:
        # provider_mode exists in both pre-M4 and M4+ releases, so this is also
        # a compatibility proof after automatic rollback to an older release.
        command = (
            "from fastapi_app.services.kali_recon_provider import provider_mode; "
            "assert provider_mode() == 'legacy'"
        )

    last_error = ""
    for _ in range(attempts):
        running = _running_services(env_file, deployment_env)
        if "scanner_worker" not in running:
            last_error = "scanner_worker is not running"
            time.sleep(3)
            continue
        if active_kali and "kali_recon" not in running:
            last_error = "active governed Kali Recon execution requires running kali_recon service"
            time.sleep(3)
            continue
        try:
            _run(
                _compose(
                    env_file,
                    "exec",
                    "-T",
                    "scanner_worker",
                    "python",
                    "-c",
                    command,
                ),
                cwd=PLATFORM_DIR,
                env=deployment_env,
                timeout=20,
            )
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            last_error = str(exc)[-2000:]
            time.sleep(3)
    state = _scanner_worker_state(env_file, deployment_env)
    raise DeployError(f"Recon execution-plane acceptance did not become healthy: {last_error}; {state}")


def _accept(origin: str, attempts: int = 40) -> None:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "public_acceptance.py"),
        "--origin",
        origin,
    ]
    last_error = ""
    for _ in range(attempts):
        result = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True)
        if result.returncode == 0:
            return
        last_error = (result.stderr or result.stdout).strip()[-4000:]
        time.sleep(3)
    raise DeployError(f"public acceptance did not become healthy: {last_error}")


def _checkout(sha: str) -> None:
    _git("checkout", "--detach", sha, capture=False)


def _restore_tracked_checkout(sha: str) -> None:
    """Discard only tracked mutations created after the clean deployment boundary."""
    if not SHA_RE.fullmatch(sha):
        raise DeployError("checkout restore SHA must be exactly 40 lowercase hexadecimal characters")
    dirty = _git("status", "--porcelain", "--untracked-files=no").stdout.strip()
    if not dirty:
        return
    if _current_sha() != sha:
        raise DeployError("dirty checkout no longer matches the interrupted release SHA")
    _git("reset", "--hard", sha, capture=False)
    if _current_sha() != sha:
        raise DeployError("tracked checkout restore changed the release SHA unexpectedly")
    _assert_clean_repo()


def _rollback_application(
    *,
    previous_sha: str,
    failed_release_sha: str,
    env_file: Path,
    previous_env_snapshot: tuple[bytes, int, int],
    origin: str,
) -> None:
    migrations = _migration_changes(previous_sha, failed_release_sha)
    if migrations:
        raise DeployError(
            "automatic rollback blocked because database migrations changed; "
            "restore the pre-deploy backup before rolling application code back. "
            f"changed migrations: {migrations[:20]}"
        )

    _restore_private_env(env_file, previous_env_snapshot)
    previous_env = _load_env_file(env_file)
    rollback_env = _rollback_execution_environment({**os.environ, **previous_env})
    _checkout(previous_sha)
    _build_stack(env_file, rollback_env)
    _assert_storage_floor("before-service-start")
    _deploy_stack(env_file, rollback_env)
    _execution_plane_acceptance(env_file, rollback_env)
    _accept(origin)


def deploy(release_sha: str, env_file: Path, origin: str) -> dict[str, object]:
    origin = _validate_origin(origin)
    _assert_clean_repo()
    _ensure_release(release_sha)
    env_values = _load_env_file(env_file)
    previous_env_snapshot = _snapshot_private_env(env_file)
    deployment_env = _execution_profile_environment({**os.environ, **env_values})
    previous_sha = _current_sha()
    backup = _backup_before_upgrade(env_file, deployment_env)
    storage_reclaim = _host_storage_reclaim()

    deployment_attempted = False
    try:
        _checkout(release_sha)
        env_values = _prepare_execution_trust(env_file, release_sha)
        deployment_env = _execution_profile_environment({**os.environ, **env_values})
        _preflight(env_file, deployment_env)
        build_storage = _build_stack(env_file, deployment_env)
        _assert_storage_floor("before-service-start")
        # Build failures have not changed the running services. Restore only
        # checkout/env in that case; a rollback rebuild can fail for the same
        # capacity reason and conceal the original failure.
        deployment_attempted = True
        _deploy_stack(env_file, deployment_env)
        _execution_plane_acceptance(env_file, deployment_env)
        _accept(origin)
    except BaseException as failure:
        # The repository was proven clean before this attempt. Any tracked
        # mutation now belongs to the interrupted/failed deployment and must
        # not poison the next fail-closed rollout.
        _restore_tracked_checkout(release_sha)
        if deployment_attempted:
            if previous_sha != release_sha:
                try:
                    _rollback_application(
                        previous_sha=previous_sha,
                        failed_release_sha=release_sha,
                        env_file=env_file,
                        previous_env_snapshot=previous_env_snapshot,
                        origin=origin,
                    )
                except Exception as rollback_failure:
                    raise DeployError(
                        f"production deployment failed: {failure}; "
                        f"automatic rollback also failed: {rollback_failure}"
                    ) from failure
            else:
                _restore_private_env(env_file, previous_env_snapshot)
        else:
            _restore_private_env(env_file, previous_env_snapshot)
            if previous_sha != release_sha:
                _checkout(previous_sha)
        raise

    result: dict[str, object] = {
        "schema": "aegisscan.production-deploy.v1",
        "status": "success",
        "previous_sha": previous_sha,
        "release_sha": release_sha,
        "public_origin": origin,
        "pre_deploy_backup": backup,
        "storage_reclaim": storage_reclaim,
        "application_build_storage": build_storage,
    }
    print(json.dumps(result, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    args = parser.parse_args()
    handled_signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        handled_signals.append(signal.SIGHUP)
    previous_handlers = {sig: signal.getsignal(sig) for sig in handled_signals}
    for sig in handled_signals:
        signal.signal(sig, _deployment_signal_handler)
    try:
        deploy(args.release_sha, args.env_file.resolve(), args.origin.strip())
    except (DeployError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({
            "schema": "aegisscan.production-deploy.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
