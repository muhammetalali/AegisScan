#!/usr/bin/env python3
"""Reclaim only non-durable Docker storage before an internal production rollout."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

GIB = 1024 ** 3
DEFAULT_PATH = Path("/opt/aegisscan/AegisScan/aegis-platform")
DEFAULT_MINIMUM_FREE_BYTES = 60 * GIB
DEFAULT_TARGET_FREE_BYTES = 68 * GIB
MAX_DIAGNOSTIC_BYTES = 16 * 1024


class StorageReclaimError(RuntimeError):
    pass


def _free_bytes(path: Path) -> int:
    if not path.exists():
        raise StorageReclaimError(f"storage path does not exist: {path}")
    return shutil.disk_usage(path).free


def _run(argv: list[str], *, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            check=True,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        if len(detail) > 4000:
            detail = detail[-4000:]
        suffix = f": {detail}" if detail else ""
        raise StorageReclaimError(
            f"command failed: {' '.join(argv)}: exit={exc.returncode}{suffix}"
        ) from exc
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise StorageReclaimError(f"command failed: {' '.join(argv)}: {exc}") from exc


def _docker_ready() -> None:
    if shutil.which("docker") is None:
        raise StorageReclaimError("docker CLI is unavailable on the production runner")
    _run(["docker", "info"], timeout=60)


def _docker_df() -> str:
    result = _run(["docker", "system", "df"], timeout=60)
    text = result.stdout.strip()
    return text[-MAX_DIAGNOSTIC_BYTES:]


def _execute_stage(name: str, argv: list[str], *, path: Path) -> dict[str, object]:
    before = _free_bytes(path)
    result = _run(argv, timeout=1800)
    after = _free_bytes(path)
    return {
        "name": name,
        "argv": argv,
        "before_free_bytes": before,
        "after_free_bytes": after,
        "reclaimed_bytes": max(0, after - before),
        "stdout_tail": result.stdout.strip()[-4000:],
    }


def reclaim(
    *,
    path: Path = DEFAULT_PATH,
    minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES,
    target_free_bytes: int = DEFAULT_TARGET_FREE_BYTES,
    defer_on_docker_unavailable: bool = False,
) -> dict[str, object]:
    path = path.resolve()
    if minimum_free_bytes <= 0:
        raise StorageReclaimError("minimum free bytes must be positive")
    if target_free_bytes < minimum_free_bytes:
        raise StorageReclaimError("target free bytes must be greater than or equal to minimum free bytes")

    before = _free_bytes(path)
    result: dict[str, object] = {
        "schema": "aegisscan.production-storage-reclaim.v1",
        "status": "success",
        "path": str(path),
        "minimum_free_bytes": minimum_free_bytes,
        "target_free_bytes": target_free_bytes,
        "before_free_bytes": before,
        "after_free_bytes": before,
        "reclaimed_bytes": 0,
        "stages": [],
        "volume_prune_performed": False,
        "deferred_to_privileged_deploy": False,
    }

    if before >= target_free_bytes:
        result["mode"] = "noop-capacity-already-sufficient"
        return result

    try:
        _docker_ready()
        result["docker_df_before"] = _docker_df()
    except StorageReclaimError as exc:
        if defer_on_docker_unavailable:
            result["mode"] = "deferred-to-privileged-production-deploy"
            result["docker_reclaim_available"] = False
            result["docker_reclaim_error"] = str(exc)
            result["deferred_to_privileged_deploy"] = True
            return result
        if before < minimum_free_bytes:
            raise StorageReclaimError(
                "free disk is below the production minimum and Docker reclaim is unavailable: "
                f"{before} < {minimum_free_bytes}: {exc}"
            ) from exc
        result["mode"] = "minimum-preserved-docker-unavailable"
        result["docker_reclaim_available"] = False
        result["docker_reclaim_error"] = str(exc)
        return result

    result["docker_reclaim_available"] = True

    stages: list[tuple[str, list[str]]] = [
        (
            "aged-build-cache",
            ["docker", "builder", "prune", "--all", "--force", "--filter", "until=24h"],
        ),
        (
            "aged-stopped-containers",
            ["docker", "container", "prune", "--force", "--filter", "until=24h"],
        ),
        (
            "aged-unused-images",
            ["docker", "image", "prune", "--all", "--force", "--filter", "until=24h"],
        ),
    ]

    stage_results: list[dict[str, object]] = []
    for name, argv in stages:
        stage_results.append(_execute_stage(name, argv, path=path))
        if _free_bytes(path) >= target_free_bytes:
            break

    after_aged = _free_bytes(path)
    if after_aged < minimum_free_bytes:
        aggressive_stages: list[tuple[str, list[str]]] = [
            (
                "all-build-cache",
                ["docker", "builder", "prune", "--all", "--force"],
            ),
            (
                "all-stopped-containers",
                ["docker", "container", "prune", "--force"],
            ),
            (
                "all-unused-images",
                ["docker", "image", "prune", "--all", "--force"],
            ),
        ]
        for name, argv in aggressive_stages:
            stage_results.append(_execute_stage(name, argv, path=path))
            if _free_bytes(path) >= target_free_bytes:
                break

    after = _free_bytes(path)
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
        raise StorageReclaimError(
            "bounded Docker reclaim completed without touching volumes, "
            f"but free disk is still below the production minimum: {after} < {minimum_free_bytes}"
        )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH)
    parser.add_argument(
        "--minimum-free-gib",
        type=int,
        default=DEFAULT_MINIMUM_FREE_BYTES // GIB,
    )
    parser.add_argument(
        "--target-free-gib",
        type=int,
        default=DEFAULT_TARGET_FREE_BYTES // GIB,
    )
    parser.add_argument(
        "--defer-on-docker-unavailable",
        action="store_true",
        help="Defer the hard capacity gate to the privileged production deploy when the runner cannot access Docker.",
    )
    args = parser.parse_args()

    try:
        result = reclaim(
            path=args.path,
            minimum_free_bytes=args.minimum_free_gib * GIB,
            target_free_bytes=args.target_free_gib * GIB,
            defer_on_docker_unavailable=args.defer_on_docker_unavailable,
        )
    except StorageReclaimError as exc:
        print(
            json.dumps(
                {
                    "schema": "aegisscan.production-storage-reclaim.v1",
                    "status": "failed",
                    "error": str(exc),
                    "volume_prune_performed": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
