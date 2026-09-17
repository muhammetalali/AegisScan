#!/usr/bin/env python3
"""Plan and optionally apply safe AegisScan branch hygiene.

Only refs proven to be merged ancestors of the current default branch, with no open
pull request and an unchanged live SHA, can be deleted. Historical archive and backup
refs are never deletion candidates.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
AUTO_PREFIXES = ("chatgpt-a/", "codex/", "sol-worker/")
B_PREFIX = "chatgpt-b/"
PROTECTED_PREFIXES = ("archive/", "backup/")


class HygieneError(RuntimeError):
    pass


def _api_json(method: str, path: str, token: str) -> Any:
    url = path if path.startswith("https://") else f"{API_ROOT}{path}"
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AegisScan-branch-hygiene",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise HygieneError(f"GitHub API {method} {url} failed: {exc.code}: {detail[:800]}") from exc
    except urllib.error.URLError as exc:
        raise HygieneError(f"GitHub API {method} {url} failed: {exc}") from exc


def _paginate(repo: str, suffix: str, token: str) -> list[dict[str, Any]]:
    separator = "&" if "?" in suffix else "?"
    page = 1
    out: list[dict[str, Any]] = []
    while True:
        payload = _api_json("GET", f"/repos/{repo}{suffix}{separator}per_page=100&page={page}", token)
        if not isinstance(payload, list):
            raise HygieneError(f"unexpected paginated response for {suffix}")
        out.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < 100:
            return out
        page += 1


def _commit_time(repo: str, sha: str, token: str) -> dt.datetime:
    payload = _api_json("GET", f"/repos/{repo}/commits/{sha}", token)
    if not isinstance(payload, dict):
        raise HygieneError(f"unexpected commit payload for {sha}")
    commit = payload.get("commit") or {}
    committer = commit.get("committer") or {}
    value = committer.get("date")
    if not isinstance(value, str):
        raise HygieneError(f"commit {sha} has no committer date")
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _compare(repo: str, branch: str, default_branch: str, token: str) -> dict[str, Any]:
    base = urllib.parse.quote(branch, safe="")
    head = urllib.parse.quote(default_branch, safe="")
    payload = _api_json("GET", f"/repos/{repo}/compare/{base}...{head}", token)
    if not isinstance(payload, dict):
        raise HygieneError(f"unexpected compare payload for {branch}")
    return payload


def classify_branch(
    *,
    name: str,
    sha: str,
    default_branch: str,
    open_heads: set[str],
    compare_status: str | None,
    ahead_by: int | None,
    behind_by: int | None,
    age_hours: float | None,
    min_age_hours: int,
    include_chatgpt_b: bool,
) -> tuple[str, bool, str]:
    if name == default_branch:
        return "default_branch", False, "default branch is never a hygiene target"
    if name.startswith("archive/"):
        return "historical_archive", False, "archive refs are retained for provenance"
    if name.startswith("backup/"):
        return "safety_backup", False, "backup refs require explicit human retirement"
    if name in open_heads:
        return "active_work", False, "branch is the head of an open pull request"
    if compare_status is None:
        return "unclassified", False, "comparison to default branch was not available"
    if compare_status not in {"ahead", "identical"} or (behind_by or 0) != 0:
        return "diverged_or_unmerged", False, "branch tip is not proven to be an ancestor of default branch"
    if age_hours is None or age_hours < min_age_hours:
        return "recent_merged", False, "merged ancestor has not reached the retention threshold"
    allowed = name.startswith(AUTO_PREFIXES) or (include_chatgpt_b and name.startswith(B_PREFIX))
    if not allowed:
        return "merged_retained", False, "prefix is not approved for automatic hygiene"
    return "safe_merged_candidate", True, "tip is an aged merged ancestor, has no open PR, and uses an approved prefix"


def _open_heads(repo: str, token: str) -> set[str]:
    pulls = _paginate(repo, "/pulls?state=open", token)
    heads: set[str] = set()
    for pr in pulls:
        head = pr.get("head") or {}
        head_repo = head.get("repo") or {}
        ref = head.get("ref")
        if head_repo.get("full_name") == repo and isinstance(ref, str):
            heads.add(ref)
    return heads


def _live_ref_sha(repo: str, branch: str, token: str) -> str | None:
    encoded = urllib.parse.quote(f"heads/{branch}", safe="/")
    try:
        payload = _api_json("GET", f"/repos/{repo}/git/ref/{encoded}", token)
    except HygieneError as exc:
        if "failed: 404:" in str(exc):
            return None
        raise
    obj = (payload or {}).get("object") or {}
    value = obj.get("sha")
    return value if isinstance(value, str) else None


def build_plan(repo: str, token: str, min_age_hours: int, include_chatgpt_b: bool) -> dict[str, Any]:
    repository = _api_json("GET", f"/repos/{repo}", token)
    if not isinstance(repository, dict) or not isinstance(repository.get("default_branch"), str):
        raise HygieneError("repository default branch is unavailable")
    default_branch = repository["default_branch"]
    branches = _paginate(repo, "/branches", token)
    open_heads = _open_heads(repo, token)
    now = dt.datetime.now(dt.timezone.utc)
    inventory: list[dict[str, Any]] = []
    for branch in branches:
        name = branch.get("name")
        sha = ((branch.get("commit") or {}).get("sha"))
        if not isinstance(name, str) or not isinstance(sha, str):
            continue
        compare_status: str | None = None
        ahead_by: int | None = None
        behind_by: int | None = None
        age_hours: float | None = None
        if name != default_branch and not name.startswith(PROTECTED_PREFIXES) and name not in open_heads:
            comparison = _compare(repo, name, default_branch, token)
            compare_status = comparison.get("status") if isinstance(comparison.get("status"), str) else None
            ahead_by = int(comparison.get("ahead_by") or 0)
            behind_by = int(comparison.get("behind_by") or 0)
            committed_at = _commit_time(repo, sha, token)
            age_hours = max(0.0, (now - committed_at).total_seconds() / 3600.0)
        category, deletable, reason = classify_branch(
            name=name,
            sha=sha,
            default_branch=default_branch,
            open_heads=open_heads,
            compare_status=compare_status,
            ahead_by=ahead_by,
            behind_by=behind_by,
            age_hours=age_hours,
            min_age_hours=min_age_hours,
            include_chatgpt_b=include_chatgpt_b,
        )
        inventory.append(
            {
                "name": name,
                "sha": sha,
                "category": category,
                "deletable": deletable,
                "reason": reason,
                "compare_status": compare_status,
                "ahead_by": ahead_by,
                "behind_by": behind_by,
                "age_hours": None if age_hours is None else round(age_hours, 2),
            }
        )
    return {
        "schema": "aegis.branch-hygiene-plan.v1",
        "repository": repo,
        "default_branch": default_branch,
        "default_sha": next((item["sha"] for item in inventory if item["name"] == default_branch), None),
        "min_age_hours": min_age_hours,
        "include_chatgpt_b": include_chatgpt_b,
        "open_pr_heads": sorted(open_heads),
        "inventory": sorted(inventory, key=lambda item: item["name"]),
        "delete_candidates": sorted(item["name"] for item in inventory if item["deletable"]),
    }


def apply_plan(repo: str, token: str, plan: dict[str, Any]) -> list[dict[str, str]]:
    # Re-evaluate the entire plan immediately before deletion so stale evidence cannot authorize a mutation.
    fresh = build_plan(repo, token, int(plan["min_age_hours"]), bool(plan["include_chatgpt_b"]))
    fresh_by_name = {item["name"]: item for item in fresh["inventory"]}
    deleted: list[dict[str, str]] = []
    for name in plan["delete_candidates"]:
        original = next(item for item in plan["inventory"] if item["name"] == name)
        current = fresh_by_name.get(name)
        if current is None:
            continue
        if not current.get("deletable"):
            raise HygieneError(f"candidate {name} is no longer deletable: {current.get('reason')}")
        if current.get("sha") != original.get("sha"):
            raise HygieneError(f"candidate {name} advanced from {original.get('sha')} to {current.get('sha')}")
        live_sha = _live_ref_sha(repo, name, token)
        if live_sha != original.get("sha"):
            raise HygieneError(f"candidate {name} live ref changed before deletion")
        encoded = urllib.parse.quote(f"heads/{name}", safe="/")
        _api_json("DELETE", f"/repos/{repo}/git/refs/{encoded}", token)
        deleted.append({"name": name, "sha": str(original["sha"])})
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--min-age-hours", type=int, default=24)
    parser.add_argument("--include-chatgpt-b", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    repo = args.repo.strip()
    if not REPO_RE.fullmatch(repo):
        raise HygieneError("--repo must be owner/name")
    if args.min_age_hours < 1:
        raise HygieneError("--min-age-hours must be at least 1")
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise HygieneError("GITHUB_TOKEN is required")
    plan = build_plan(repo, token, args.min_age_hours, args.include_chatgpt_b)
    result: dict[str, Any] = {"plan": plan, "deleted": []}
    if args.mode == "apply":
        result["deleted"] = apply_plan(repo, token, plan)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print("BRANCH_HYGIENE_PASS")
    print(text)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HygieneError as exc:
        print(f"BRANCH_HYGIENE_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
