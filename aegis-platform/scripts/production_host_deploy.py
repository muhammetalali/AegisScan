#!/usr/bin/env python3
"""Fail-closed production host deployment orchestrator for AegisScan."""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SCRIPT_DIR = Path(__file__).resolve().parent
PLATFORM_DIR = SCRIPT_DIR.parent
REPO_ROOT = PLATFORM_DIR.parent
COMPOSE_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
    "docker-compose.backup.yml",
)


class DeployError(RuntimeError):
    pass


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


def _compose(env_file: Path, *args: str) -> list[str]:
    argv = ["docker", "compose", "--env-file", str(env_file)]
    for name in COMPOSE_FILES:
        argv.extend(["-f", str(PLATFORM_DIR / name)])
    argv.extend(args)
    return argv


def _git(*args: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["git", *args], capture=capture, timeout=600)


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
        ["git", "merge-base", "--is-ancestor", release_sha, "origin/main"],
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
            "python",
            "/app/scripts/remote_backup_service.py",
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


def _deploy_stack(env_file: Path, deployment_env: dict[str, str]) -> None:
    _run(
        _compose(env_file, "build", "--pull"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        capture=False,
        timeout=7200,
    )
    _run(
        _compose(env_file, "up", "-d", "--remove-orphans"),
        cwd=PLATFORM_DIR,
        env=deployment_env,
        capture=False,
        timeout=1800,
    )


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


def _rollback_application(
    *,
    previous_sha: str,
    failed_release_sha: str,
    env_file: Path,
    deployment_env: dict[str, str],
    origin: str,
) -> None:
    migrations = _migration_changes(previous_sha, failed_release_sha)
    if migrations:
        raise DeployError(
            "automatic rollback blocked because database migrations changed; "
            "restore the pre-deploy backup before rolling application code back. "
            f"changed migrations: {migrations[:20]}"
        )
    _checkout(previous_sha)
    _deploy_stack(env_file, deployment_env)
    _accept(origin)


def deploy(release_sha: str, env_file: Path, origin: str) -> dict[str, object]:
    _assert_clean_repo()
    _ensure_release(release_sha)
    env_values = _load_env_file(env_file)
    deployment_env = {**os.environ, **env_values}
    previous_sha = _current_sha()
    _preflight(env_file, deployment_env)
    backup = _backup_before_upgrade(env_file, deployment_env)

    _checkout(release_sha)
    try:
        _preflight(env_file, deployment_env)
        _deploy_stack(env_file, deployment_env)
        _accept(origin)
    except BaseException:
        if previous_sha != release_sha:
            _rollback_application(
                previous_sha=previous_sha,
                failed_release_sha=release_sha,
                env_file=env_file,
                deployment_env=deployment_env,
                origin=origin,
            )
        raise

    result: dict[str, object] = {
        "schema": "aegisscan.production-deploy.v1",
        "status": "success",
        "previous_sha": previous_sha,
        "release_sha": release_sha,
        "public_origin": origin,
        "pre_deploy_backup": backup,
    }
    print(json.dumps(result, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--origin", required=True)
    args = parser.parse_args()
    try:
        deploy(args.release_sha, args.env_file.resolve(), args.origin.strip())
    except (DeployError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({
            "schema": "aegisscan.production-deploy.v1",
            "status": "failed",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
