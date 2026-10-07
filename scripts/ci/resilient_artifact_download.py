#!/usr/bin/env python3
"""Fail-closed GitHub Actions artifact download with bounded transient retries."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


_TRANSIENT_MARKERS = (
    "http 429",
    "http 500",
    "http 502",
    "http 503",
    "http 504",
    "egress is over the account limit",
    "econnreset",
    "connection reset",
    "timed out",
    "timeout",
    "temporary failure",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
)


class ArtifactDownloadError(RuntimeError):
    pass


def _is_transient(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in _TRANSIENT_MARKERS)


def _safe_diagnostic(message: str) -> str:
    sanitized = re.sub(r"https?://\S+", "<url-redacted>", message)
    return sanitized[:2000]


def _regular_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()]


def download_artifact(
    *,
    run_id: int,
    repository: str,
    destination: Path,
    artifact_name: str | None = None,
    runner=subprocess.run,
    sleeper=time.sleep,
) -> int:
    if run_id <= 0:
        raise ArtifactDownloadError("run id must be positive")
    if "/" not in repository or repository.startswith("/") or repository.endswith("/"):
        raise ArtifactDownloadError("repository must be in owner/name form")

    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise ArtifactDownloadError(f"destination is not empty: {destination}")

    root_parent = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
    root_parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="aegis-artifact-download-", dir=root_parent))
    backoffs = (10, 30)

    try:
        for attempt in range(1, 4):
            attempt_dir = scratch / f"attempt-{attempt}"
            attempt_dir.mkdir(mode=0o700)

            command = ["gh", "run", "download", str(run_id), "--repo", repository]
            if artifact_name:
                command.extend(["--name", artifact_name])
            command.extend(["--dir", str(attempt_dir)])

            result = runner(command, capture_output=True, text=True)
            combined = "\n".join(
                part.strip() for part in (result.stdout or "", result.stderr or "") if part.strip()
            )
            if result.returncode == 0:
                if any(path.is_symlink() for path in attempt_dir.rglob("*")):
                    raise ArtifactDownloadError("artifact contains a symlink")
                files = _regular_files(attempt_dir)
                if not files:
                    raise ArtifactDownloadError(
                        "artifact download reported success but produced no regular files"
                    )
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                if any(destination.iterdir()):
                    raise ArtifactDownloadError(
                        f"destination became non-empty during download: {destination}"
                    )
                for child in attempt_dir.iterdir():
                    target = destination / child.name
                    if child.is_symlink():
                        raise ArtifactDownloadError("artifact root contains a symlink")
                    if child.is_dir():
                        shutil.copytree(child, target, symlinks=False)
                    else:
                        shutil.copy2(child, target, follow_symlinks=False)
                copied = _regular_files(destination)
                if len(copied) != len(files):
                    raise ArtifactDownloadError("artifact copy verification failed")
                print(
                    "AEGISSCAN_ARTIFACT_DOWNLOAD=PASS "
                    f"attempt={attempt} run_id={run_id} "
                    f"name={artifact_name or '<all>'} files={len(copied)}"
                )
                return attempt

            diagnostic = _safe_diagnostic(combined)
            print(
                "artifact download attempt failed "
                f"attempt={attempt} run_id={run_id} "
                f"name={artifact_name or '<all>'}: {diagnostic}",
                flush=True,
            )
            if not _is_transient(combined):
                raise ArtifactDownloadError(
                    f"artifact download failed with a non-transient error: {diagnostic}"
                )
            if attempt == 3:
                raise ArtifactDownloadError(
                    "all bounded transient artifact download attempts failed"
                )
            sleeper(backoffs[attempt - 1])

        raise AssertionError("unreachable")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-name")
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()

    try:
        download_artifact(
            run_id=args.run_id,
            repository=args.repository,
            artifact_name=args.artifact_name,
            destination=args.destination,
        )
    except ArtifactDownloadError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
