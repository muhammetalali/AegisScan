#!/usr/bin/env python3
"""Verify AegisScan fresh-main final state from independently retained exact-SHA evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.ci.release1_version import RELEASE_TAG

SCHEMA = "aegisscan.fresh-main-final-verification.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class FinalVerificationError(RuntimeError):
    pass


def _load(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 32 * 1024 * 1024:
        raise FinalVerificationError(f"{label} is missing or has invalid size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalVerificationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise FinalVerificationError(f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_companion_sha256(data_path: Path, checksum_path: Path, label: str) -> str:
    if not data_path.is_file():
        raise FinalVerificationError(f"{label} evidence file is missing")
    if not checksum_path.is_file() or checksum_path.stat().st_size <= 0 or checksum_path.stat().st_size > 4096:
        raise FinalVerificationError(f"{label} companion SHA256 file is missing or has invalid size")
    try:
        raw = checksum_path.read_text(encoding="utf-8").strip()
    except UnicodeDecodeError as exc:
        raise FinalVerificationError(f"{label} companion SHA256 is not UTF-8 text") from exc
    parts = raw.split()
    if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
        raise FinalVerificationError(f"{label} companion SHA256 format is invalid")
    referenced = parts[1].lstrip("*")
    if Path(referenced).name != data_path.name:
        raise FinalVerificationError(f"{label} companion SHA256 references the wrong evidence file")
    actual = _sha256(data_path)
    if actual != parts[0]:
        raise FinalVerificationError(f"{label} companion SHA256 mismatch")
    return actual


def _require_embedded_digest(value: dict[str, Any], *, field: str, label: str) -> None:
    supplied = str(value.get(field) or "")
    if not SHA256_RE.fullmatch(supplied):
        raise FinalVerificationError(f"{label} embedded digest is missing or invalid")
    unsigned = dict(value)
    unsigned.pop(field, None)
    raw = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    expected = hashlib.sha256(raw).hexdigest()
    if supplied != expected:
        raise FinalVerificationError(f"{label} embedded digest mismatch")


def _require_decision(
    path: Path,
    *,
    schema: str,
    status: str,
    decision: str,
    release_sha: str,
    label: str,
) -> dict[str, Any]:
    value = _load(path, label)
    checks = {
        "schema": value.get("schema") == schema,
        "status": value.get("status") == status,
        "decision": value.get("decision") == decision,
        "release_sha": value.get("release_sha") == release_sha,
        "controls": isinstance(value.get("controls"), dict)
        and bool(value["controls"])
        and all(value["controls"].values()),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        raise FinalVerificationError(f"{label} failed checks: {failures}")
    return value


def _require_run(
    path: Path,
    *,
    name: str,
    workflow_path: str,
    release_sha: str,
    repository: str,
    events: set[str],
) -> dict[str, Any]:
    run = _load(path, f"{name} workflow metadata")
    repo = run.get("repository") or {}
    checks = {
        "name": run.get("name") == name,
        "path": run.get("path") == workflow_path,
        "status": run.get("status") == "completed",
        "conclusion": run.get("conclusion") == "success",
        "head_sha": run.get("head_sha") == release_sha,
        "head_branch": run.get("head_branch") == "main",
        "repository": isinstance(repo, dict) and repo.get("full_name") == repository,
        "event": run.get("event") in events,
    }
    failures = [key for key, passed in checks.items() if not passed]
    if failures:
        raise FinalVerificationError(f"{name} workflow metadata failed checks: {failures}")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    if not isinstance(run_id, int) or run_id <= 0 or not isinstance(attempt, int) or attempt <= 0:
        raise FinalVerificationError(f"{name} workflow run identity is invalid")
    return {"run_id": run_id, "run_attempt": attempt, "event": run.get("event")}


def build_verification(
    *,
    release_sha: str,
    repository: str,
    repository_state: Path,
    release_metadata: Path,
    release_tag_metadata: Path,
    required_ci_run: Path,
    release_closure_run: Path,
    provider_closure_run: Path,
    performance_run: Path,
    hygiene_run: Path,
    release_closure: Path,
    release_closure_sha256: Path,
    provider_closure: Path,
    provider_closure_sha256: Path,
    performance_acceptance: Path,
    performance_acceptance_sha256: Path,
    hygiene: Path,
    hygiene_sha256: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = release_sha.strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise FinalVerificationError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if repository.strip() != "muhammetalali/AegisScan":
        raise FinalVerificationError("fresh-main verification is bound to the canonical AegisScan repository")

    state = _load(repository_state, "repository state")
    if (
        state.get("repository") != repository
        or state.get("default_branch") != "main"
        or state.get("main_sha") != release_sha
        or state.get("open_pr_count") != 0
    ):
        raise FinalVerificationError("repository state is not zero-drift exact main")

    release = _load(release_metadata, "GitHub Release metadata")
    tag = _load(release_tag_metadata, "GitHub Release tag metadata")
    if (
        release.get("tagName") != RELEASE_TAG
        or release.get("targetCommitish") != release_sha
        or release.get("isDraft") is not False
        or release.get("isPrerelease") is not False
    ):
        raise FinalVerificationError("GitHub Release is not the final exact-SHA Release 1 object")
    tag_object = tag.get("object") or {}
    if tag_object.get("type") != "commit" or tag_object.get("sha") != release_sha:
        raise FinalVerificationError(f"{RELEASE_TAG} tag does not point directly to the exact release commit")

    run_summaries = {
        "Required CI Governance": _require_run(
            required_ci_run,
            name="Required CI Governance",
            workflow_path=".github/workflows/required-ci-governance.yml",
            release_sha=release_sha,
            repository=repository,
            events={"push"},
        ),
        "Release 1 Closure": _require_run(
            release_closure_run,
            name="Release 1 Closure",
            workflow_path=".github/workflows/release1-closure.yml",
            release_sha=release_sha,
            repository=repository,
            events={"workflow_run", "workflow_dispatch"},
        ),
        "External Provider Acceptance Closure": _require_run(
            provider_closure_run,
            name="External Provider Acceptance Closure",
            workflow_path=".github/workflows/external-provider-acceptance-closure.yml",
            release_sha=release_sha,
            repository=repository,
            events={"workflow_dispatch"},
        ),
        "Performance Load Soak Reality": _require_run(
            performance_run,
            name="Performance Load Soak Reality",
            workflow_path=".github/workflows/performance-load-soak-reality.yml",
            release_sha=release_sha,
            repository=repository,
            events={"workflow_dispatch"},
        ),
        "Final Project Hygiene": _require_run(
            hygiene_run,
            name="Final Project Hygiene",
            workflow_path=".github/workflows/final-project-hygiene.yml",
            release_sha=release_sha,
            repository=repository,
            events={"workflow_dispatch"},
        ),
    }

    release_value = _require_decision(
        release_closure,
        schema="aegisscan.release1-closure.v1",
        status="success",
        decision="RELEASED",
        release_sha=release_sha,
        label="Release 1 closure",
    )
    # The release1-closure.v1 producer publishes the canonical string "1".
    if release_value.get("release") != "1":
        raise FinalVerificationError("Release 1 closure release number mismatch")

    _require_embedded_digest(
        release_value,
        field="release_closure_sha256",
        label="Release 1 closure",
    )

    provider_value = _require_decision(
        provider_closure,
        schema="aegisscan.external-provider-acceptance-closure.v1",
        status="success",
        decision="ACCEPTED",
        release_sha=release_sha,
        label="external provider closure",
    )
    _require_embedded_digest(
        provider_value,
        field="closure_sha256",
        label="external provider closure",
    )
    performance_value = _require_decision(
        performance_acceptance,
        schema="aegisscan.release-performance-acceptance.v1",
        status="success",
        decision="ACCEPTED",
        release_sha=release_sha,
        label="release performance acceptance",
    )
    if performance_value.get("profile") != "release":
        raise FinalVerificationError("performance acceptance is not the final release profile")
    _require_embedded_digest(
        performance_value,
        field="acceptance_sha256",
        label="release performance acceptance",
    )
    hygiene_value = _require_decision(
        hygiene,
        schema="aegisscan.final-project-hygiene.v1",
        status="success",
        decision="CLEAN",
        release_sha=release_sha,
        label="final project hygiene",
    )
    if hygiene_value.get("open_pr_count") != 0 or hygiene_value.get("safe_branch_candidates_after") != []:
        raise FinalVerificationError("final project hygiene is not fully clean")

    _require_embedded_digest(
        hygiene_value,
        field="hygiene_sha256",
        label="final project hygiene",
    )

    artifacts = {
        "release1-closure.json": _require_companion_sha256(
            release_closure, release_closure_sha256, "Release 1 closure"
        ),
        "external-provider-acceptance-closure.json": _require_companion_sha256(
            provider_closure, provider_closure_sha256, "external provider closure"
        ),
        "release-performance-acceptance.json": _require_companion_sha256(
            performance_acceptance, performance_acceptance_sha256, "release performance acceptance"
        ),
        "final-project-hygiene.json": _require_companion_sha256(
            hygiene, hygiene_sha256, "final project hygiene"
        ),
    }
    if not all(SHA256_RE.fullmatch(value) for value in artifacts.values()):
        raise FinalVerificationError("final evidence digest generation failed")

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "success",
        "decision": "VERIFIED",
        "repository": repository,
        "release": 1,
        "release_tag": RELEASE_TAG,
        "release_sha": release_sha,
        "main_sha": release_sha,
        "open_pr_count": 0,
        "workflow_runs": run_summaries,
        "artifact_sha256": artifacts,
        "controls": {
            "fresh_main_exact_release_sha": True,
            "required_ci_success": True,
            "release1_released": True,
            "github_release_exact_tag": True,
            "external_providers_accepted": True,
            "release_performance_accepted": True,
            "final_hygiene_clean": True,
            "zero_open_prs": True,
            "zero_sha_drift": True,
        },
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["verification_sha256"] = hashlib.sha256(raw).hexdigest()
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
    parser.add_argument("--required-ci-run", type=Path, required=True)
    parser.add_argument("--release-closure-run", type=Path, required=True)
    parser.add_argument("--provider-closure-run", type=Path, required=True)
    parser.add_argument("--performance-run", type=Path, required=True)
    parser.add_argument("--hygiene-run", type=Path, required=True)
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--release-closure-sha256", type=Path, required=True)
    parser.add_argument("--provider-closure", type=Path, required=True)
    parser.add_argument("--provider-closure-sha256", type=Path, required=True)
    parser.add_argument("--performance-acceptance", type=Path, required=True)
    parser.add_argument("--performance-acceptance-sha256", type=Path, required=True)
    parser.add_argument("--hygiene", type=Path, required=True)
    parser.add_argument("--hygiene-sha256", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_verification(
            release_sha=args.release_sha,
            repository=args.repository,
            repository_state=args.repository_state,
            release_metadata=args.release_metadata,
            release_tag_metadata=args.release_tag_metadata,
            required_ci_run=args.required_ci_run,
            release_closure_run=args.release_closure_run,
            provider_closure_run=args.provider_closure_run,
            performance_run=args.performance_run,
            hygiene_run=args.hygiene_run,
            release_closure=args.release_closure,
            release_closure_sha256=args.release_closure_sha256,
            provider_closure=args.provider_closure,
            provider_closure_sha256=args.provider_closure_sha256,
            performance_acceptance=args.performance_acceptance,
            performance_acceptance_sha256=args.performance_acceptance_sha256,
            hygiene=args.hygiene,
            hygiene_sha256=args.hygiene_sha256,
            output=args.output,
        )
    except FinalVerificationError as exc:
        print(f"FRESH_MAIN_FINAL_VERIFICATION_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
