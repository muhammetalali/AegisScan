#!/usr/bin/env python3
"""Fail-closed aggregator for AegisScan pull-request and main CI reality."""

from __future__ import annotations

import fnmatch
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
SUPPORTED_EVENTS = {"pull_request", "push"}
COMPARE_FILE_CAP = 300


class GovernanceError(RuntimeError):
    pass


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise GovernanceError(f"required environment variable is missing: {name}")
    return value


def _api_json(path: str, token: str) -> Any:
    url = path if path.startswith("https://") else f"{API_ROOT}{path}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AegisScan-required-ci-governance",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise GovernanceError(f"GitHub API request failed: {exc.code} {url}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise GovernanceError(f"GitHub API request failed: {url}: {exc}") from exc


def _paginate(repo: str, suffix: str, token: str, item_key: str | None = None) -> list[dict[str, Any]]:
    separator = "&" if "?" in suffix else "?"
    page = 1
    items: list[dict[str, Any]] = []
    while True:
        payload = _api_json(f"/repos/{repo}{suffix}{separator}per_page=100&page={page}", token)
        page_items = payload[item_key] if item_key else payload
        if not isinstance(page_items, list):
            raise GovernanceError(f"unexpected paginated GitHub response for {suffix}")
        items.extend(item for item in page_items if isinstance(item, dict))
        if len(page_items) < 100:
            return items
        page += 1


def _load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if policy.get("schema_version") != 1:
        raise GovernanceError("unsupported required CI policy schema_version")
    if not isinstance(policy.get("governance_workflow"), str) or not policy["governance_workflow"]:
        raise GovernanceError("governance_workflow must be a non-empty string")
    if policy.get("successful_conclusions") != ["success"]:
        raise GovernanceError("successful_conclusions must remain fail-closed as ['success']")
    if not isinstance(policy.get("observe_all_triggered_workflows"), bool):
        raise GovernanceError("observe_all_triggered_workflows must be boolean")
    for key in ("poll_seconds", "settle_seconds", "timeout_seconds"):
        value = policy.get(key)
        if not isinstance(value, int) or value <= 0:
            raise GovernanceError(f"{key} must be a positive integer")
    if policy["timeout_seconds"] <= policy["settle_seconds"]:
        raise GovernanceError("timeout_seconds must exceed settle_seconds")
    always = policy.get("always_required_workflows")
    if not isinstance(always, dict):
        raise GovernanceError("always_required_workflows must be an object")
    for event, names in always.items():
        if event not in SUPPORTED_EVENTS:
            raise GovernanceError(f"unsupported policy event: {event}")
        if not isinstance(names, list) or not names or any(not isinstance(name, str) or not name for name in names):
            raise GovernanceError(f"always_required_workflows[{event}] must be a non-empty string list")
        if len(names) != len(set(names)):
            raise GovernanceError(f"duplicate always-required workflow for event {event}")
    conditional = policy.get("conditional_required_workflows")
    if not isinstance(conditional, list):
        raise GovernanceError("conditional_required_workflows must be a list")
    for rule in conditional:
        if not isinstance(rule, dict) or set(rule) != {"name", "events", "paths"}:
            raise GovernanceError(f"conditional workflow rule has unexpected fields: {sorted(rule) if isinstance(rule, dict) else type(rule).__name__}")
        if not isinstance(rule["name"], str) or not rule["name"]:
            raise GovernanceError("conditional workflow name must be non-empty")
        if not isinstance(rule["events"], list) or not rule["events"]:
            raise GovernanceError(f"conditional workflow {rule['name']} has no events")
        if any(event not in SUPPORTED_EVENTS for event in rule["events"]):
            raise GovernanceError(f"conditional workflow {rule['name']} has unsupported event")
        if not isinstance(rule["paths"], list) or not rule["paths"]:
            raise GovernanceError(f"conditional workflow {rule['name']} has no paths")
        if any(not isinstance(pattern, str) or not pattern for pattern in rule["paths"]):
            raise GovernanceError(f"conditional workflow {rule['name']} has invalid path pattern")
    return policy


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _required_workflows(policy: dict[str, Any], event_name: str, changed_paths: list[str]) -> set[str]:
    required = set(policy["always_required_workflows"].get(event_name, []))
    for rule in policy["conditional_required_workflows"]:
        if event_name in rule["events"] and any(_matches_any(path, rule["paths"]) for path in changed_paths):
            required.add(rule["name"])
    return required


def _pull_request_changed_paths(
    repo: str,
    base_ref: str,
    head_sha: str,
    token: str,
) -> tuple[list[str], str]:
    """Derive the PR diff from the live base branch, never GitHub's stale PR file cache."""
    if not base_ref:
        raise GovernanceError("pull_request event is missing base.ref")
    if not head_sha:
        raise GovernanceError("pull_request event is missing head.sha")

    encoded_base = urllib.parse.quote(base_ref, safe="")
    branch_payload = _api_json(f"/repos/{repo}/branches/{encoded_base}", token)
    if not isinstance(branch_payload, dict):
        raise GovernanceError(f"GitHub returned an unexpected live base branch response for {base_ref}")
    live_base_sha = str((branch_payload.get("commit") or {}).get("sha") or "")
    if not live_base_sha:
        raise GovernanceError(f"live base branch {base_ref!r} has no commit SHA")

    base_sha_q = urllib.parse.quote(live_base_sha, safe="")
    head_sha_q = urllib.parse.quote(head_sha, safe="")
    comparison = _api_json(f"/repos/{repo}/compare/{base_sha_q}...{head_sha_q}", token)
    if not isinstance(comparison, dict):
        raise GovernanceError("GitHub returned an unexpected live-base compare response")

    merge_base_sha = str((comparison.get("merge_base_commit") or {}).get("sha") or "")
    if merge_base_sha != live_base_sha:
        raise GovernanceError(
            f"pull request head {head_sha} is stale relative to live {base_ref}@{live_base_sha}; "
            f"merge base is {merge_base_sha or 'unknown'}"
        )
    status = comparison.get("status")
    if status not in {"ahead", "identical"}:
        raise GovernanceError(
            f"pull request head {head_sha} is not a clean descendant of live {base_ref}@{live_base_sha}: {status!r}"
        )

    files = comparison.get("files")
    if not isinstance(files, list):
        raise GovernanceError("live-base compare did not expose changed files")
    if len(files) >= COMPARE_FILE_CAP:
        raise GovernanceError(
            f"live-base compare reached the GitHub {COMPARE_FILE_CAP}-file cap; "
            "split the pull request or extend the governance verifier before merge"
        )
    changed_paths = sorted(
        {item["filename"] for item in files if isinstance(item, dict) and isinstance(item.get("filename"), str)}
    )
    return changed_paths, live_base_sha


def _push_changed_paths(repo: str, event: dict[str, Any], token: str) -> list[str]:
    before = str(event.get("before") or "")
    after = str(event.get("after") or "")
    if not after:
        return []
    if before and before != "0" * 40:
        payload = _api_json(f"/repos/{repo}/compare/{before}...{after}", token)
        files = payload.get("files") or []
    else:
        payload = _api_json(f"/repos/{repo}/commits/{after}", token)
        files = payload.get("files") or []
    return sorted({item["filename"] for item in files if isinstance(item, dict) and isinstance(item.get("filename"), str)})


def _workflow_runs(repo: str, sha: str, event_name: str, token: str, head_ref: str) -> dict[str, dict[str, Any]]:
    query = urllib.parse.urlencode({"head_sha": sha, "event": event_name})
    runs = _paginate(repo, f"/actions/runs?{query}", token, item_key="workflow_runs")
    latest: dict[str, dict[str, Any]] = {}
    for run in runs:
        if run.get("head_sha") != sha or run.get("event") != event_name:
            continue
        if head_ref and run.get("head_branch") != head_ref:
            continue
        name = run.get("name")
        if not isinstance(name, str) or not name:
            continue
        previous = latest.get(name)
        key = (int(run.get("run_attempt") or 0), int(run.get("id") or 0))
        previous_key = (int(previous.get("run_attempt") or 0), int(previous.get("id") or 0)) if previous else (-1, -1)
        if previous is None or key > previous_key:
            latest[name] = run
    return latest


def _run_summary(run: dict[str, Any]) -> dict[str, Any]:
    return {key: run.get(key) for key in ("id", "name", "status", "conclusion", "run_attempt", "html_url")}


def main() -> int:
    if len(sys.argv) != 2:
        raise GovernanceError("usage: required_ci_governance.py POLICY_JSON")
    policy = _load_policy(Path(sys.argv[1]))
    token = _required_env("GITHUB_TOKEN")
    repo = _required_env("GITHUB_REPOSITORY")
    event_name = _required_env("GITHUB_EVENT_NAME")
    sha = _required_env("GITHUB_SHA")
    head_ref = os.environ.get("GITHUB_HEAD_REF", "").strip() or os.environ.get("GITHUB_REF_NAME", "").strip()
    event = json.loads(Path(_required_env("GITHUB_EVENT_PATH")).read_text(encoding="utf-8"))
    if event_name not in SUPPORTED_EVENTS:
        raise GovernanceError(f"unsupported event for required CI governance: {event_name}")

    live_base_sha: str | None = None
    changed_path_source = "push-event"
    if event_name == "pull_request":
        pr = event.get("pull_request") or {}
        sha = str((pr.get("head") or {}).get("sha") or sha)
        head_ref = str((pr.get("head") or {}).get("ref") or head_ref)
        base_ref = str((pr.get("base") or {}).get("ref") or "")
        changed_paths, live_base_sha = _pull_request_changed_paths(repo, base_ref, sha, token)
        changed_path_source = "live-base-compare"
    else:
        changed_paths = _push_changed_paths(repo, event, token)

    expected = _required_workflows(policy, event_name, changed_paths)
    self_workflow = policy["governance_workflow"]
    successful = set(policy["successful_conclusions"])
    poll_seconds = policy["poll_seconds"]
    settle_seconds = policy["settle_seconds"]
    deadline = time.monotonic() + policy["timeout_seconds"]
    stable_since: float | None = None
    stable_signature: tuple[tuple[Any, ...], ...] | None = None
    last_log = 0.0

    print(
        json.dumps(
            {
                "event": event_name,
                "head_sha": sha,
                "head_ref": head_ref,
                "live_base_sha": live_base_sha,
                "changed_path_source": changed_path_source,
                "changed_paths": changed_paths,
                "expected_workflows": sorted(expected),
                "observe_all_triggered_workflows": policy["observe_all_triggered_workflows"],
            },
            indent=2,
            sort_keys=True,
        )
    )

    while time.monotonic() < deadline:
        runs = _workflow_runs(repo, sha, event_name, token, head_ref)
        runs.pop(self_workflow, None)
        observed_names = set(runs)
        missing = sorted(expected - observed_names)
        governed_names = observed_names if policy["observe_all_triggered_workflows"] else expected
        pending = sorted(name for name in governed_names if name in runs and runs[name].get("status") != "completed")
        failed = sorted(
            name
            for name in governed_names
            if name in runs and runs[name].get("status") == "completed" and runs[name].get("conclusion") not in successful
        )
        if failed:
            details = [_run_summary(runs[name]) for name in failed]
            raise GovernanceError(
                f"required/triggered CI workflow failure on exact SHA {sha}: {json.dumps(details, sort_keys=True)}"
            )
        if not missing and not pending:
            signature = tuple(
                sorted(
                    (name, runs[name].get("id"), runs[name].get("run_attempt"), runs[name].get("conclusion"))
                    for name in governed_names
                    if name in runs
                )
            )
            if signature != stable_signature:
                stable_signature = signature
                stable_since = time.monotonic()
                print(f"All governed workflows are successful; entering {settle_seconds}s quiescence window.")
            elif stable_since is not None and time.monotonic() - stable_since >= settle_seconds:
                proof = {
                    "event": event_name,
                    "head_sha": sha,
                    "live_base_sha": live_base_sha,
                    "changed_path_source": changed_path_source,
                    "required_workflows": sorted(expected),
                    "observed_successful_workflows": sorted(governed_names),
                    "workflow_runs": [_run_summary(runs[name]) for name in sorted(governed_names)],
                }
                print("REQUIRED_CI_GOVERNANCE_PASS")
                print(json.dumps(proof, indent=2, sort_keys=True))
                return 0
        else:
            stable_since = None
            stable_signature = None
        now = time.monotonic()
        if now - last_log >= 60:
            print(json.dumps({"waiting": True, "missing": missing, "pending": pending, "observed": sorted(observed_names)}, sort_keys=True))
            last_log = now
        time.sleep(poll_seconds)

    runs = _workflow_runs(repo, sha, event_name, token, head_ref)
    runs.pop(self_workflow, None)
    missing = sorted(expected - set(runs))
    pending = sorted(name for name, run in runs.items() if run.get("status") != "completed")
    raise GovernanceError(f"required CI governance timed out for exact SHA {sha}; missing={missing}; pending={pending}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GovernanceError as exc:
        print(f"REQUIRED_CI_GOVERNANCE_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
