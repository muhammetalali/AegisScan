#!/usr/bin/env python3
"""Build the exact-SHA AegisScan Release 1 closure manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "aegisscan.release1-closure.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_RUNS = {
    "Required CI Governance": (".github/workflows/required-ci-governance.yml", {"push"}),
    "Repository Governance Reality": (".github/workflows/repository-governance-reality.yml", {"push"}),
    "Final Red Blue SRE Acceptance": (".github/workflows/final-red-blue-sre-acceptance.yml", {"push"}),
    "Final Governance Closure": (".github/workflows/final-governance-closure.yml", {"push"}),
    "Supply Chain Release": (".github/workflows/supply-chain-release.yml", {"push"}),
    "Production Host Reality": (".github/workflows/production-host-reality.yml", {"push"}),
    "Production Launch Readiness": (".github/workflows/production-launch-readiness.yml", {"push"}),
    "Internal Production Deploy and Acceptance": (
        ".github/workflows/production-live-deploy.yml",
        {"push", "workflow_dispatch"},
    ),
    "Production Resilience Acceptance": (
        ".github/workflows/production-resilience-acceptance.yml",
        {"workflow_run", "workflow_dispatch"},
    ),
    "Final Internal Production Governance": (
        ".github/workflows/production-final-governance.yml",
        {"workflow_run", "workflow_dispatch"},
    ),
}


class ReleaseClosureError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ReleaseClosureError(f"{label} does not exist: {path}")
    size = path.stat().st_size
    if size <= 0 or size > 16 * 1024 * 1024:
        raise ReleaseClosureError(f"{label} has invalid size")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseClosureError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ReleaseClosureError(f"{label} must contain a JSON object")
    return payload


def _unique(root: Path, name: str, label: str) -> Path:
    matches = [path for path in root.rglob(name) if path.is_file()]
    if len(matches) != 1:
        raise ReleaseClosureError(f"{label} must contain exactly one {name}; found {len(matches)}")
    return matches[0]


def _verify_runs(*, root: Path, release_sha: str, repository: str) -> dict[str, dict[str, Any]]:
    runs: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*.json")):
        payload = _load_json(path, f"workflow metadata {path.name}")
        name = payload.get("name")
        if name in REQUIRED_RUNS:
            if name in runs:
                raise ReleaseClosureError(f"duplicate workflow metadata for {name}")
            runs[str(name)] = payload

    missing = sorted(set(REQUIRED_RUNS) - set(runs))
    if missing:
        raise ReleaseClosureError(f"missing required release workflow metadata: {missing}")

    normalized: dict[str, dict[str, Any]] = {}
    for name, (expected_path, allowed_events) in REQUIRED_RUNS.items():
        run = runs[name]
        repository_payload = run.get("repository") or {}
        checks = {
            "status": run.get("status") == "completed",
            "conclusion": run.get("conclusion") == "success",
            "head_sha": run.get("head_sha") == release_sha,
            "head_branch": run.get("head_branch") == "main",
            "path": run.get("path") == expected_path,
            "event": run.get("event") in allowed_events,
            "repository": repository_payload.get("full_name") == repository,
        }
        failures = [key for key, value in checks.items() if not value]
        if failures:
            raise ReleaseClosureError(f"{name} workflow metadata failed checks: {failures}")
        run_id = run.get("id")
        attempt = run.get("run_attempt")
        if not isinstance(run_id, int) or run_id <= 0:
            raise ReleaseClosureError(f"{name} workflow run id is invalid")
        if not isinstance(attempt, int) or attempt <= 0:
            raise ReleaseClosureError(f"{name} workflow run attempt is invalid")
        jobs = run.get("jobs")
        if not isinstance(jobs, list) or not jobs:
            raise ReleaseClosureError(f"{name} has no executed job evidence")
        for job in jobs:
            if (
                not isinstance(job, dict)
                or job.get("run_id") != run_id
                or job.get("run_attempt") != attempt
                or job.get("head_sha") != release_sha
                or job.get("status") != "completed"
                or job.get("conclusion") != "success"
                or not job.get("steps")
            ):
                raise ReleaseClosureError(f"{name} contains missing, skipped, failed or mismatched job evidence")
        required_job = {
            "Internal Production Deploy and Acceptance": "deploy-and-accept",
            "Production Resilience Acceptance": "resilience-acceptance",
            "Final Internal Production Governance": "final-governance",
        }.get(name)
        if required_job and required_job not in {job.get("name") for job in jobs}:
            raise ReleaseClosureError(f"{name} did not execute required job {required_job}")
        normalized[name] = {
            "run_id": run_id,
            "run_attempt": attempt,
            "event": run.get("event"),
            "path": expected_path,
            "updated_at": run.get("updated_at"),
        }
    return normalized


def _verify_final_acceptance(root: Path, release_sha: str) -> dict[str, Any]:
    path = _unique(root, "final-red-blue-sre-acceptance.json", "final Red/Blue/SRE evidence")
    payload = _load_json(path, "final Red/Blue/SRE evidence")
    if payload.get("schema") != "aegisscan.final-red-blue-sre-acceptance.v1":
        raise ReleaseClosureError("final Red/Blue/SRE schema mismatch")
    if payload.get("status") != "success" or payload.get("decision") != "ACCEPTED":
        raise ReleaseClosureError("final Red/Blue/SRE acceptance is not successful")
    if payload.get("release_sha") != release_sha:
        raise ReleaseClosureError("final Red/Blue/SRE release SHA mismatch")
    if not SHA256_RE.fullmatch(str(payload.get("acceptance_sha256") or "")):
        raise ReleaseClosureError("final Red/Blue/SRE acceptance digest is invalid")
    return {"sha256": _sha256_file(path), "decision": "ACCEPTED"}


def _verify_final_governance(root: Path, release_sha: str) -> dict[str, Any]:
    path = _unique(root, "final-governance-closure.json", "final governance evidence")
    payload = _load_json(path, "final governance evidence")
    if payload.get("schema") != "aegisscan.final-governance-closure.v1":
        raise ReleaseClosureError("final governance schema mismatch")
    if payload.get("status") != "success" or payload.get("decision") != "APPROVED":
        raise ReleaseClosureError("final governance is not approved")
    if payload.get("release_sha") != release_sha:
        raise ReleaseClosureError("final governance release SHA mismatch")
    if not SHA256_RE.fullmatch(str(payload.get("governance_sha256") or "")):
        raise ReleaseClosureError("final governance digest is invalid")
    return {"sha256": _sha256_file(path), "decision": "APPROVED"}


def _verify_production_governance(root: Path, release_sha: str) -> dict[str, Any]:
    path = _unique(root, "decision.json", "final production governance evidence")
    payload = _load_json(path, "final production governance evidence")
    if payload.get("schema") != "aegisscan.production-governance-decision.v2":
        raise ReleaseClosureError("final production governance schema mismatch")
    if payload.get("status") != "success" or payload.get("decision") != "APPROVED":
        raise ReleaseClosureError("final production governance is not approved")
    if payload.get("release_sha") != release_sha:
        raise ReleaseClosureError("final production governance release SHA mismatch")
    if payload.get("deployment_mode") != "internal":
        raise ReleaseClosureError("final production governance is not internal production")
    return {
        "sha256": _sha256_file(path),
        "decision": "APPROVED",
        "internal_origin": str(payload.get("internal_origin") or ""),
    }


def _verify_supply_chain(root: Path, release_sha: str, repository: str, run_id: int) -> dict[str, str]:
    digests: dict[str, str] = {}
    for component in ("django", "fastapi", "frontend"):
        for suffix in ("cdx.json", "provenance.json"):
            name = f"{component}.{suffix}"
            path = _unique(root, name, "supply-chain release evidence")
            payload = _load_json(path, name)
            if suffix == "cdx.json":
                if payload.get("bomFormat") != "CycloneDX" or not payload.get("components"):
                    raise ReleaseClosureError(f"{name} is not a populated CycloneDX SBOM")
            else:
                source = (payload.get("invocation") or {}).get("configSource") or {}
                if (
                    (source.get("digest") or {}).get("sha1") != release_sha
                    or source.get("uri") != f"git+https://github.com/{repository}@refs/heads/main"
                    or source.get("entryPoint") != REQUIRED_RUNS["Supply Chain Release"][0]
                    or (payload.get("builder") or {}).get("id") != f"https://github.com/{repository}/actions/runs/{run_id}"
                ):
                    raise ReleaseClosureError(f"{name} provenance does not match the exact release build")
            digests[name] = _sha256_file(path)
    return dict(sorted(digests.items()))


def _verify_repository_state(path: Path, release_sha: str, repository: str) -> dict[str, Any]:
    payload = _load_json(path, "repository state")
    if payload.get("repository") != repository:
        raise ReleaseClosureError("repository state repository mismatch")
    if payload.get("default_branch") != "main":
        raise ReleaseClosureError("repository default branch is not main")
    if payload.get("main_sha") != release_sha:
        raise ReleaseClosureError("repository state main SHA mismatch")
    if payload.get("open_pr_count") != 0:
        raise ReleaseClosureError("release closure requires zero open pull requests")
    return payload


def _verify_branch_hygiene(path: Path, release_sha: str, repository: str) -> dict[str, Any]:
    payload = _load_json(path, "branch hygiene evidence")
    plan = payload.get("plan")
    deleted = payload.get("deleted")
    if not isinstance(plan, dict) or not isinstance(deleted, list):
        raise ReleaseClosureError("branch hygiene evidence shape is invalid")
    if plan.get("schema") != "aegis.branch-hygiene-plan.v1":
        raise ReleaseClosureError("branch hygiene schema mismatch")
    if plan.get("repository") != repository or plan.get("default_branch") != "main":
        raise ReleaseClosureError("branch hygiene repository mismatch")
    if plan.get("default_sha") != release_sha:
        raise ReleaseClosureError("branch hygiene default SHA mismatch")
    if plan.get("open_pr_heads"):
        raise ReleaseClosureError("branch hygiene observed active pull-request heads")
    candidates = set(plan.get("delete_candidates") or [])
    deleted_names = {
        str(item.get("name"))
        for item in deleted
        if isinstance(item, dict) and item.get("name")
    }
    if candidates != deleted_names:
        raise ReleaseClosureError(
            f"branch hygiene did not close every safe merged candidate: "
            f"candidates={sorted(candidates)} deleted={sorted(deleted_names)}"
        )
    return {
        "inventory_count": len(plan.get("inventory") or []),
        "deleted_safe_merged_branches": sorted(deleted_names),
        "sha256": _sha256_file(path),
    }


def build_manifest(
    *,
    release_sha: str,
    repository: str,
    metadata_root: Path,
    evidence_root: Path,
    repository_state: Path,
    branch_hygiene: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = str(release_sha or "").strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise ReleaseClosureError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if not repository or "/" not in repository:
        raise ReleaseClosureError("repository must be owner/name")
    metadata_root = metadata_root.resolve()
    evidence_root = evidence_root.resolve()
    if not metadata_root.is_dir() or not evidence_root.is_dir():
        raise ReleaseClosureError("release metadata/evidence roots must exist")

    runs = _verify_runs(root=metadata_root, release_sha=release_sha, repository=repository)
    state = _verify_repository_state(repository_state.resolve(), release_sha, repository)
    hygiene = _verify_branch_hygiene(branch_hygiene.resolve(), release_sha, repository)
    acceptance = _verify_final_acceptance(evidence_root, release_sha)
    governance = _verify_final_governance(evidence_root, release_sha)
    production = _verify_production_governance(evidence_root, release_sha)
    supply_chain = _verify_supply_chain(evidence_root, release_sha, repository, runs["Supply Chain Release"]["run_id"])

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "success",
        "decision": "RELEASED",
        "release": "1",
        "release_sha": release_sha,
        "repository": repository,
        "controls": {
            "exact_main_sha": True,
            "zero_open_pull_requests": True,
            "required_ci_green": True,
            "repository_governance_green": True,
            "red_blue_sre_accepted": True,
            "final_governance_approved": True,
            "supply_chain_signed_attested": True,
            "internal_production_deployed": True,
            "backup_restore_resilience_proven": True,
            "final_production_governance_approved": True,
            "branch_hygiene_applied": True,
        },
        "workflow_runs": runs,
        "repository_state": {
            "main_sha": state["main_sha"],
            "open_pr_count": 0,
        },
        "branch_hygiene": hygiene,
        "evidence": {
            "final_red_blue_sre": acceptance,
            "final_governance": governance,
            "final_production_governance": production,
            "supply_chain": supply_chain,
        },
    }
    payload["release_closure_sha256"] = _sha256_bytes(_canonical(payload))
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--metadata-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--repository-state", type=Path, required=True)
    parser.add_argument("--branch-hygiene", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build_manifest(
            release_sha=args.release_sha,
            repository=args.repository,
            metadata_root=args.metadata_root,
            evidence_root=args.evidence_root,
            repository_state=args.repository_state,
            branch_hygiene=args.branch_hygiene,
            output=args.output,
        )
    except ReleaseClosureError as exc:
        print(
            json.dumps(
                {"schema": SCHEMA, "status": "failed", "decision": "REJECTED", "error": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
