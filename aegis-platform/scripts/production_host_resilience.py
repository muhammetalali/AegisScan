#!/usr/bin/env python3
"""Fixed, exact-release backup and application recovery actions for the installed gate."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import production_host_deploy as host


def execute(*, action: str, release_sha: str, env_file: Path, origin: str = "") -> dict:
    if not host.SHA_RE.fullmatch(release_sha) or action not in {"backup", "recover-services"}:
        raise host.DeployError("invalid resilience action or release SHA")
    host._assert_clean_repo()
    if host._current_sha() != release_sha:
        raise host.DeployError("production host checkout does not match the resilience release SHA")
    env = host._execution_profile_environment(host._load_env_file(env_file))
    # The privileged gate supplies a sanitized PATH and CA trust. Keep those values.
    env = {**host.os.environ, **env}
    if "postgres" not in host._running_services(env_file, env):
        raise host.DeployError("production PostgreSQL is not running")
    if action == "backup":
        result = host._run(host._compose(env_file, "run", "--rm", "--no-deps", "backup", "once"),
                           cwd=host.PLATFORM_DIR, env=env, timeout=14400)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        try:
            payload = json.loads(lines[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise host.DeployError("backup did not return durable JSON") from exc
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise host.DeployError("backup did not succeed")
        for key in ("backup_id", "manifest_key", "manifest_version_id", "object_version_id"):
            if not payload.get(key) or payload[key] == "null":
                raise host.DeployError(f"backup is missing durable {key}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("source_sha256", ""))):
            raise host.DeployError("backup source digest is invalid")
        payload["release_sha"] = release_sha
    else:
        origin = host._validate_origin(origin)
        host._run(host._compose(env_file, "restart", "fastapi"), cwd=host.PLATFORM_DIR, env=env, timeout=180)
        host._execution_plane_acceptance(env_file, env)
        host._accept(origin)
        payload = {"schema": "aegisscan.production-service-recovery.v1", "status": "success",
                   "release_sha": release_sha, "restarted_services": ["fastapi"],
                   "https_acceptance": True, "execution_plane_healthy": True}
    if host._current_sha() != release_sha:
        raise host.DeployError("production release changed during resilience acceptance")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=["backup", "recover-services"], required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--origin", default="")
    args = parser.parse_args()
    try:
        result = execute(action=args.action, release_sha=args.release_sha, env_file=args.env_file, origin=args.origin)
    except (host.DeployError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
