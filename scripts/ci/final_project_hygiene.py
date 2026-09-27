#!/usr/bin/env python3
"""Build the post-release AegisScan final project hygiene decision."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "aegisscan.final-project-hygiene.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

EXTERNAL_REQUESTS = (
    ".github/live-acceptance-requests/cloud-providers.json",
    ".github/live-acceptance-requests/external-identity.json",
    ".github/live-acceptance-requests/performance.json",
)
PRODUCTION_REQUEST = ".github/deployment-requests/internal-production.json"


class FinalHygieneError(RuntimeError):
    pass


def _load(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 32 * 1024 * 1024:
        raise FinalHygieneError(f"{label} is missing or has invalid size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalHygieneError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise FinalHygieneError(f"{label} must be a JSON object")
    return value


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_hygiene(
    *,
    release_sha: str,
    repository: str,
    repo_root: Path,
    repository_state: Path,
    apply_result: Path,
    post_plan: Path,
    release_metadata: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = release_sha.strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise FinalHygieneError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if repository.strip() != "muhammetalali/AegisScan":
        raise FinalHygieneError("final project hygiene is bound to the canonical AegisScan repository")
    repo_root = repo_root.resolve()

    state = _load(repository_state, "repository state")
    apply = _load(apply_result, "branch hygiene apply result")
    post = _load(post_plan, "branch hygiene post-plan result")
    release = _load(release_metadata, "GitHub Release metadata")

    state_checks = {
        "repository": state.get("repository") == repository,
        "default_branch": state.get("default_branch") == "main",
        "main_sha": state.get("main_sha") == release_sha,
        "open_pr_count": state.get("open_pr_count") == 0,
    }
    failures = [name for name, passed in state_checks.items() if not passed]
    if failures:
        raise FinalHygieneError(f"repository state failed checks: {failures}")

    if (
        release.get("tagName") != "v1.0.0"
        or release.get("targetCommitish") != release_sha
        or release.get("isDraft") is not False
        or release.get("isPrerelease") is not False
    ):
        raise FinalHygieneError("GitHub Release 1 metadata does not match the exact final SHA")

    applied_plan = apply.get("plan")
    deleted = apply.get("deleted")
    if not isinstance(applied_plan, dict) or not isinstance(deleted, list):
        raise FinalHygieneError("branch hygiene apply evidence is malformed")
    candidates = applied_plan.get("delete_candidates")
    if not isinstance(candidates, list):
        raise FinalHygieneError("branch hygiene apply plan has no candidate list")
    deleted_names = {
        str(item.get("name"))
        for item in deleted
        if isinstance(item, dict) and item.get("name")
    }
    if set(map(str, candidates)) != deleted_names:
        raise FinalHygieneError("branch hygiene did not delete every safe candidate from its applied plan")
    if applied_plan.get("default_branch") != "main" or applied_plan.get("default_sha") != release_sha:
        raise FinalHygieneError("branch hygiene apply plan is not bound to exact final main")
    if applied_plan.get("open_pr_heads") != []:
        raise FinalHygieneError("branch hygiene apply plan observed an open PR head")
    if applied_plan.get("include_chatgpt_b") is not True:
        raise FinalHygieneError("final project hygiene must explicitly include merged chatgpt-b branches")

    post_plan_obj = post.get("plan")
    if not isinstance(post_plan_obj, dict):
        raise FinalHygieneError("post-cleanup branch plan is malformed")
    if post_plan_obj.get("default_sha") != release_sha:
        raise FinalHygieneError("post-cleanup branch plan drifted from exact final SHA")
    if post_plan_obj.get("open_pr_heads") != []:
        raise FinalHygieneError("post-cleanup branch plan still contains open PR heads")
    if post_plan_obj.get("delete_candidates") != []:
        raise FinalHygieneError(
            f"post-cleanup branch plan still contains safe deletion candidates: {post_plan_obj.get('delete_candidates')}"
        )

    for relative in EXTERNAL_REQUESTS:
        if (repo_root / relative).exists():
            raise FinalHygieneError(f"expired external live request is still retained: {relative}")

    production_request_path = repo_root / PRODUCTION_REQUEST
    production_request: dict[str, Any] | None = None
    production_request_reusable = False
    if production_request_path.is_file():
        production_request = _load(production_request_path, "historical internal production request")
        if production_request.get("schema") != "aegisscan.internal-production-deployment-request.v1":
            raise FinalHygieneError("historical internal production request schema mismatch")
        base = str(production_request.get("requested_base_sha") or "")
        if not SHA_RE.fullmatch(base):
            raise FinalHygieneError("historical internal production request base SHA is invalid")
        if base == release_sha:
            raise FinalHygieneError("historical internal production request unexpectedly targets the final release SHA")
        production_request_reusable = False

    inventory = post_plan_obj.get("inventory")
    if not isinstance(inventory, list) or not inventory:
        raise FinalHygieneError("post-cleanup branch inventory is missing")
    retained_by_category: dict[str, int] = {}
    for item in inventory:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "unclassified")
        retained_by_category[category] = retained_by_category.get(category, 0) + 1

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "success",
        "decision": "CLEAN",
        "repository": repository,
        "release_sha": release_sha,
        "release_tag": "v1.0.0",
        "open_pr_count": 0,
        "safe_branch_candidates_before": sorted(map(str, candidates)),
        "safe_branches_deleted": sorted(deleted_names),
        "safe_branch_candidates_after": [],
        "retained_branch_categories": retained_by_category,
        "external_live_request_files": {path: "absent" for path in EXTERNAL_REQUESTS},
        "historical_production_request_present": production_request is not None,
        "historical_production_request_reusable": production_request_reusable,
        "controls": {
            "exact_main": True,
            "published_release_exact_sha": True,
            "zero_open_prs": True,
            "safe_merged_branch_cleanup_applied": True,
            "no_safe_candidates_remaining": True,
            "archives_and_backups_policy_retained": True,
            "expired_external_requests_absent": True,
            "production_request_not_reusable": True,
        },
    }
    payload["hygiene_sha256"] = _canonical_sha256(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--repository-state", type=Path, required=True)
    parser.add_argument("--apply-result", type=Path, required=True)
    parser.add_argument("--post-plan", type=Path, required=True)
    parser.add_argument("--release-metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_hygiene(
            release_sha=args.release_sha,
            repository=args.repository,
            repo_root=args.repo_root,
            repository_state=args.repository_state,
            apply_result=args.apply_result,
            post_plan=args.post_plan,
            release_metadata=args.release_metadata,
            output=args.output,
        )
    except FinalHygieneError as exc:
        print(f"FINAL_PROJECT_HYGIENE_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
