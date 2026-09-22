#!/usr/bin/env python3
"""Build the fail-closed exact-SHA AegisScan Release 1 closure manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "aegisscan.release1-closure.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMPONENTS = ("django", "fastapi", "frontend")
EXPECTED_RUNS = {
    "required_ci": ("Required CI Governance", ".github/workflows/required-ci-governance.yml", "push"),
    "final_acceptance": ("Final Red Blue SRE Acceptance", ".github/workflows/final-red-blue-sre-acceptance.yml", "push"),
    "final_governance": ("Final Governance Closure", ".github/workflows/final-governance-closure.yml", "push"),
    "supply_chain": ("Supply Chain Release", ".github/workflows/supply-chain-release.yml", "push"),
    "launch_readiness": ("Production Launch Readiness", ".github/workflows/production-launch-readiness.yml", "push"),
    "live_deploy": ("Internal Production Deploy and Acceptance", ".github/workflows/production-live-deploy.yml", "push"),
    "resilience": ("Production Resilience Acceptance", ".github/workflows/production-resilience-acceptance.yml", "workflow_run"),
    "production_governance": ("Final Internal Production Governance", ".github/workflows/production-final-governance.yml", "workflow_run"),
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
    if path.stat().st_size <= 0 or path.stat().st_size > 16 * 1024 * 1024:
        raise ReleaseClosureError(f"{label} has invalid size")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseClosureError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ReleaseClosureError(f"{label} must be a JSON object")
    return payload


def _unique(root: Path, name: str, label: str) -> Path:
    matches = [item for item in root.rglob(name) if item.is_file()]
    if len(matches) != 1:
        raise ReleaseClosureError(f"{label} must contain exactly one {name}; found {len(matches)}")
    return matches[0]


def _verify_run(path: Path, *, key: str, release_sha: str, repository: str) -> dict[str, Any]:
    payload = _load_json(path, f"{key} workflow metadata")
    expected_name, expected_path, expected_event = EXPECTED_RUNS[key]
    repo = payload.get("repository") or {}
    if (
        payload.get("name") != expected_name
        or payload.get("path") != expected_path
        or payload.get("event") != expected_event
        or payload.get("status") != "completed"
        or payload.get("conclusion") != "success"
        or payload.get("head_sha") != release_sha
        or payload.get("head_branch") != "main"
        or repo.get("full_name") != repository
    ):
        raise ReleaseClosureError(f"{key} workflow metadata is not successful exact-SHA evidence")
    run_id = payload.get("id")
    if not isinstance(run_id, int) or run_id <= 0:
        raise ReleaseClosureError(f"{key} workflow run id is invalid")
    return {
        "id": run_id,
        "name": expected_name,
        "event": expected_event,
        "path": expected_path,
        "html_url": payload.get("html_url"),
    }


def _verify_repository_state(path: Path, release_sha: str) -> dict[str, Any]:
    payload = _load_json(path, "repository release state")
    if payload.get("default_branch") != "main" or payload.get("default_branch_sha") != release_sha:
        raise ReleaseClosureError("default branch is not pinned to the release SHA")
    if payload.get("open_pull_requests") != 0:
        raise ReleaseClosureError("Release 1 requires zero open pull requests")
    if payload.get("release_pr_merged") is not True:
        raise ReleaseClosureError("release pull request is not proven merged")
    pr_number = payload.get("release_pr_number")
    if not isinstance(pr_number, int) or pr_number <= 0:
        raise ReleaseClosureError("release pull request number is invalid")
    if payload.get("release_head_branch_absent") is not True:
        raise ReleaseClosureError("merged release branch has not been removed")
    head_ref = str(payload.get("release_head_ref") or "")
    if not head_ref.startswith("chatgpt-a/release-1-closure-"):
        raise ReleaseClosureError("release pull request head is not the governed Release 1 branch")
    return {
        "release_pr_number": pr_number,
        "release_head_ref": head_ref,
        "branch_hygiene": "merged-head-absent",
        "open_pull_requests": 0,
    }


def _verify_final_governance(root: Path, release_sha: str) -> dict[str, Any]:
    path = _unique(root, "final-governance-closure.json", "final governance evidence")
    payload = _load_json(path, "final governance manifest")
    if (
        payload.get("schema") != "aegisscan.final-governance-closure.v1"
        or payload.get("status") != "success"
        or payload.get("decision") != "APPROVED"
        or payload.get("release_sha") != release_sha
        or not isinstance(payload.get("controls"), dict)
        or not payload["controls"]
        or not all(payload["controls"].values())
        or not SHA256_RE.fullmatch(str(payload.get("governance_sha256") or ""))
    ):
        raise ReleaseClosureError("final governance evidence is invalid or cross-SHA")
    return {"sha256": _sha256_file(path), "governance_sha256": payload["governance_sha256"]}


def _verify_final_acceptance(root: Path, release_sha: str) -> dict[str, Any]:
    path = _unique(root, "final-red-blue-sre-acceptance.json", "final acceptance evidence")
    payload = _load_json(path, "final Red/Blue/SRE acceptance manifest")
    if (
        payload.get("schema") != "aegisscan.final-red-blue-sre-acceptance.v1"
        or payload.get("status") != "success"
        or payload.get("decision") != "ACCEPTED"
        or payload.get("release_sha") != release_sha
        or set((payload.get("dimensions") or {}).keys()) != {"red", "blue", "sre"}
        or not isinstance(payload.get("controls"), dict)
        or not payload["controls"]
        or not all(payload["controls"].values())
        or not SHA256_RE.fullmatch(str(payload.get("acceptance_sha256") or ""))
    ):
        raise ReleaseClosureError("final Red/Blue/SRE acceptance evidence is invalid or cross-SHA")
    return {"sha256": _sha256_file(path), "acceptance_sha256": payload["acceptance_sha256"]}


def _verify_production_governance(root: Path, release_sha: str) -> dict[str, Any]:
    path = _unique(root, "decision.json", "production governance evidence")
    payload = _load_json(path, "production governance decision")
    controls = payload.get("controls")
    if (
        payload.get("schema") != "aegisscan.production-governance-decision.v2"
        or payload.get("status") != "success"
        or payload.get("decision") != "APPROVED"
        or payload.get("deployment_mode") != "internal"
        or payload.get("release_sha") != release_sha
        or not isinstance(controls, dict)
        or not controls
        or not all(controls.values())
    ):
        raise ReleaseClosureError("final production governance evidence is invalid or cross-SHA")
    return {
        "sha256": _sha256_file(path),
        "internal_origin": payload.get("internal_origin"),
        "decided_at": payload.get("decided_at"),
    }


def _verify_supply_chain(root: Path, release_sha: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for component in COMPONENTS:
        provenance = _unique(root, f"{component}.provenance.json", "supply-chain evidence")
        sbom = _unique(root, f"{component}.cdx.json", "supply-chain evidence")
        predicate = _load_json(provenance, f"{component} provenance")
        config = predicate.get("invocation", {}).get("configSource", {})
        materials = predicate.get("materials")
        parameters = predicate.get("invocation", {}).get("parameters", {})
        if (
            config.get("digest") != {"sha1": release_sha}
            or config.get("entryPoint") != ".github/workflows/supply-chain-release.yml"
            or not isinstance(materials, list)
            or not materials
            or materials[0].get("digest") != {"sha1": release_sha}
            or not str(parameters.get("image", "")).endswith(f"/aegisscan-{component}")
        ):
            raise ReleaseClosureError(f"{component} provenance is not bound to the release SHA")
        sbom_payload = _load_json(sbom, f"{component} SBOM")
        if str(sbom_payload.get("bomFormat") or "").lower() != "cyclonedx":
            raise ReleaseClosureError(f"{component} SBOM is not CycloneDX")
        result[component] = {
            "provenance_sha256": _sha256_file(provenance),
            "sbom_sha256": _sha256_file(sbom),
        }
    return result


def build_release_manifest(
    *,
    release_sha: str,
    repository: str,
    metadata_root: Path,
    final_governance_root: Path,
    final_acceptance_root: Path,
    production_governance_root: Path,
    supply_chain_root: Path,
    repository_state: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = str(release_sha or "").strip()
    if not SHA_RE.fullmatch(release_sha):
        raise ReleaseClosureError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if not repository or "/" not in repository:
        raise ReleaseClosureError("repository must be owner/name")

    runs = {
        key: _verify_run(metadata_root / f"{key}.json", key=key, release_sha=release_sha, repository=repository)
        for key in EXPECTED_RUNS
    }
    state = _verify_repository_state(repository_state, release_sha)
    final_governance = _verify_final_governance(final_governance_root, release_sha)
    final_acceptance = _verify_final_acceptance(final_acceptance_root, release_sha)
    production_governance = _verify_production_governance(production_governance_root, release_sha)
    supply_chain = _verify_supply_chain(supply_chain_root, release_sha)

    payload: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "status": "success",
        "decision": "RELEASED",
        "release": "1",
        "release_sha": release_sha,
        "repository": repository,
        "controls": {
            "exact_main_sha": True,
            "required_ci_green": True,
            "final_red_blue_sre_accepted": True,
            "final_governance_approved": True,
            "production_launch_ready": True,
            "internal_production_deployed": True,
            "backup_restore_resilience_accepted": True,
            "final_internal_production_governance_approved": True,
            "signed_attested_supply_chain": True,
            "cyclonedx_cbom_release_artifacts": True,
            "zero_open_pull_requests": True,
            "merged_release_branch_removed": True,
        },
        "repository_state": state,
        "workflow_runs": runs,
        "evidence": {
            "final_governance": final_governance,
            "final_acceptance": final_acceptance,
            "production_governance": production_governance,
            "supply_chain": supply_chain,
        },
    }
    payload["release_manifest_sha256"] = _sha256_bytes(_canonical(payload))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--metadata-root", type=Path, required=True)
    parser.add_argument("--final-governance-root", type=Path, required=True)
    parser.add_argument("--final-acceptance-root", type=Path, required=True)
    parser.add_argument("--production-governance-root", type=Path, required=True)
    parser.add_argument("--supply-chain-root", type=Path, required=True)
    parser.add_argument("--repository-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        payload = build_release_manifest(
            release_sha=args.release_sha,
            repository=args.repository,
            metadata_root=args.metadata_root.resolve(),
            final_governance_root=args.final_governance_root.resolve(),
            final_acceptance_root=args.final_acceptance_root.resolve(),
            production_governance_root=args.production_governance_root.resolve(),
            supply_chain_root=args.supply_chain_root.resolve(),
            repository_state=args.repository_state.resolve(),
            output=args.output.resolve(),
        )
    except ReleaseClosureError as exc:
        print(json.dumps({
            "schema": MANIFEST_SCHEMA,
            "status": "failed",
            "decision": "REJECTED",
            "error": str(exc),
        }, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
