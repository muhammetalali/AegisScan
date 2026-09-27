#!/usr/bin/env python3
"""Build the terminal AegisScan PROJECT_COMPLETE attestation."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "aegisscan.project-completion.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ProjectCompletionError(RuntimeError):
    pass


def _load(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 32 * 1024 * 1024:
        raise ProjectCompletionError(f"{label} is missing or has invalid size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectCompletionError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ProjectCompletionError(f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_completion(
    *,
    release_sha: str,
    repository: str,
    repository_state: Path,
    release_metadata: Path,
    release_tag_metadata: Path,
    verification_run_metadata: Path,
    fresh_verification: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = release_sha.strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise ProjectCompletionError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if repository.strip() != "muhammetalali/AegisScan":
        raise ProjectCompletionError("project completion is bound to the canonical AegisScan repository")

    state = _load(repository_state, "repository state")
    if (
        state.get("repository") != repository
        or state.get("default_branch") != "main"
        or state.get("main_sha") != release_sha
        or state.get("open_pr_count") != 0
    ):
        raise ProjectCompletionError("project completion requires zero-drift main and zero open PRs")

    release = _load(release_metadata, "GitHub Release metadata")
    tag = _load(release_tag_metadata, "GitHub Release tag metadata")
    if (
        release.get("tagName") != "v1.0.0"
        or release.get("targetCommitish") != release_sha
        or release.get("isDraft") is not False
        or release.get("isPrerelease") is not False
    ):
        raise ProjectCompletionError("GitHub Release 1 does not match the exact completion SHA")
    tag_object = tag.get("object") or {}
    if tag_object.get("type") != "commit" or tag_object.get("sha") != release_sha:
        raise ProjectCompletionError("v1.0.0 tag does not point directly to the completion SHA")

    run = _load(verification_run_metadata, "fresh-main verification workflow metadata")
    repo = run.get("repository") or {}
    run_checks = {
        "name": run.get("name") == "Fresh Main Final Verification",
        "path": run.get("path") == ".github/workflows/fresh-main-final-verification.yml",
        "status": run.get("status") == "completed",
        "conclusion": run.get("conclusion") == "success",
        "head_sha": run.get("head_sha") == release_sha,
        "head_branch": run.get("head_branch") == "main",
        "repository": isinstance(repo, dict) and repo.get("full_name") == repository,
        "event": run.get("event") == "workflow_dispatch",
    }
    failures = [name for name, passed in run_checks.items() if not passed]
    if failures:
        raise ProjectCompletionError(f"fresh-main verification run failed checks: {failures}")
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    if not isinstance(run_id, int) or run_id <= 0 or not isinstance(run_attempt, int) or run_attempt <= 0:
        raise ProjectCompletionError("fresh-main verification run identity is invalid")

    verification = _load(fresh_verification, "fresh-main final verification")
    if (
        verification.get("schema") != "aegisscan.fresh-main-final-verification.v1"
        or verification.get("status") != "success"
        or verification.get("decision") != "VERIFIED"
        or verification.get("release") != 1
        or verification.get("release_tag") != "v1.0.0"
        or verification.get("release_sha") != release_sha
        or verification.get("main_sha") != release_sha
        or verification.get("open_pr_count") != 0
        or not isinstance(verification.get("controls"), dict)
        or not verification["controls"]
        or not all(verification["controls"].values())
        or not SHA256_RE.fullmatch(str(verification.get("verification_sha256") or ""))
    ):
        raise ProjectCompletionError("fresh-main final verification is not authoritative")

    required_final_controls = {
        "release1_released",
        "external_providers_accepted",
        "release_performance_accepted",
        "final_hygiene_clean",
        "required_ci_success",
        "zero_open_prs",
        "zero_sha_drift",
    }
    if not required_final_controls <= {
        key for key, value in verification["controls"].items() if value is True
    }:
        raise ProjectCompletionError("fresh-main verification is missing required final controls")

    artifact_digest = _sha256(fresh_verification)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "success",
        "decision": "PROJECT_COMPLETE",
        "project": "AegisScan",
        "repository": repository,
        "canonical_application": "aegis-platform/",
        "canonical_branch": "main",
        "release": 1,
        "release_tag": "v1.0.0",
        "release_sha": release_sha,
        "main_sha": release_sha,
        "open_pr_count": 0,
        "fresh_main_verification": {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "verification_sha256": verification["verification_sha256"],
            "artifact_sha256": artifact_digest,
        },
        "controls": {
            "release1_released": True,
            "github_release_published": True,
            "required_ci_verified": True,
            "production_acceptance_verified": True,
            "resilience_governance_closure_verified": True,
            "external_providers_accepted": True,
            "release_performance_accepted": True,
            "final_hygiene_clean": True,
            "fresh_main_verified": True,
            "zero_open_prs": True,
            "zero_sha_drift": True,
        },
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["completion_sha256"] = hashlib.sha256(raw).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-state", type=Path, required=True)
    parser.add_argument("--release-metadata", type=Path, required=True)
    parser.add_argument("--release-tag-metadata", type=Path, required=True)
    parser.add_argument("--verification-run-metadata", type=Path, required=True)
    parser.add_argument("--fresh-verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_completion(
            release_sha=args.release_sha,
            repository=args.repository,
            repository_state=args.repository_state,
            release_metadata=args.release_metadata,
            release_tag_metadata=args.release_tag_metadata,
            verification_run_metadata=args.verification_run_metadata,
            fresh_verification=args.fresh_verification,
            output=args.output,
        )
    except ProjectCompletionError as exc:
        print(f"PROJECT_COMPLETION_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
