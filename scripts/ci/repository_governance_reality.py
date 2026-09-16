#!/usr/bin/env python3
"""Validate the AegisScan main-branch governance contract and active repository rules."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

API_ROOT = "https://api.github.com"
REQUIRED_RULE_TYPES = {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}


class GovernanceError(RuntimeError):
    pass


def _api_json(path: str, token: str) -> Any:
    url = path if path.startswith("https://") else f"{API_ROOT}{path}"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AegisScan-repository-governance-reality",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise GovernanceError(f"GitHub API request failed: {exc.code} {url}: {body[:500]}") from exc
    except urllib.error.URLError as exc:
        raise GovernanceError(f"GitHub API request failed: {url}: {exc}") from exc


def _load_spec(path: Path) -> dict[str, Any]:
    spec = json.loads(path.read_text(encoding="utf-8"))
    if spec.get("schema_version") != 1:
        raise GovernanceError("unsupported repository-governance schema_version")
    if spec.get("target_branch") != "main":
        raise GovernanceError("repository governance must target main")
    context = spec.get("required_status_context")
    if not isinstance(context, str) or not context:
        raise GovernanceError("required_status_context must be non-empty")
    ruleset = spec.get("ruleset")
    if not isinstance(ruleset, dict):
        raise GovernanceError("ruleset must be an object")
    if ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
        raise GovernanceError("ruleset must actively target branches")
    if ruleset.get("bypass_actors") != []:
        raise GovernanceError("main ruleset must not define bypass actors")
    conditions = ruleset.get("conditions") or {}
    includes = ((conditions.get("ref_name") or {}).get("include") or [])
    if "~DEFAULT_BRANCH" not in includes and "refs/heads/main" not in includes:
        raise GovernanceError("ruleset must target the default/main branch")
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        raise GovernanceError("ruleset rules must be a list")
    by_type = {rule.get("type"): rule for rule in rules if isinstance(rule, dict)}
    missing = sorted(REQUIRED_RULE_TYPES - set(by_type))
    if missing:
        raise GovernanceError(f"ruleset spec is missing mandatory rules: {missing}")
    pr_parameters = by_type["pull_request"].get("parameters") or {}
    if int(pr_parameters.get("required_approving_review_count", -1)) < 0:
        raise GovernanceError("pull-request rule must define an approval count")
    if pr_parameters.get("required_review_thread_resolution") is not True:
        raise GovernanceError("pull-request rule must require review-thread resolution")
    status_parameters = by_type["required_status_checks"].get("parameters") or {}
    if status_parameters.get("strict_required_status_checks_policy") is not True:
        raise GovernanceError("required status checks must require an up-to-date branch")
    contexts = {item.get("context") for item in status_parameters.get("required_status_checks") or [] if isinstance(item, dict)}
    if context not in contexts:
        raise GovernanceError(f"ruleset must require status context: {context}")
    return spec


def _validate_live(spec: dict[str, Any], token: str, repo: str) -> dict[str, Any]:
    branch = spec["target_branch"]
    branch_payload = _api_json(f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}", token)
    if branch_payload.get("protected") is not True:
        raise GovernanceError(f"branch {branch} is not protected")
    rules = _api_json(f"/repos/{repo}/rules/branches/{urllib.parse.quote(branch, safe='')}", token)
    if not isinstance(rules, list):
        raise GovernanceError("GitHub returned an unexpected branch-rules response")
    by_type: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        if isinstance(rule, dict) and isinstance(rule.get("type"), str):
            by_type.setdefault(rule["type"], []).append(rule)
    missing = sorted(rule_type for rule_type in REQUIRED_RULE_TYPES if not by_type.get(rule_type))
    if missing:
        raise GovernanceError(f"active main rules are missing mandatory rule types: {missing}")
    if not any((rule.get("parameters") or {}).get("required_review_thread_resolution") is True for rule in by_type["pull_request"]):
        raise GovernanceError("active pull-request rules do not require review-thread resolution")
    required_context = spec["required_status_context"]
    status_rule_ok = False
    strict_ok = False
    for rule in by_type["required_status_checks"]:
        parameters = rule.get("parameters") or {}
        strict_ok = strict_ok or parameters.get("strict_required_status_checks_policy") is True
        contexts = {item.get("context") for item in parameters.get("required_status_checks") or [] if isinstance(item, dict)}
        if required_context in contexts:
            status_rule_ok = True
    if not status_rule_ok:
        raise GovernanceError(f"active rules do not require status context: {required_context}")
    if not strict_ok:
        raise GovernanceError("active required-status-check rule is not strict/up-to-date")
    return {
        "repository": repo,
        "branch": branch,
        "branch_sha": (branch_payload.get("commit") or {}).get("sha"),
        "protected": True,
        "active_rule_types": sorted(by_type),
        "required_status_context": required_context,
        "strict_status_checks": True,
        "pull_request_required": True,
        "force_push_blocked": True,
        "deletion_blocked": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("--mode", choices=("spec", "live"), required=True)
    args = parser.parse_args()
    spec = _load_spec(args.spec)
    if args.mode == "spec":
        print("REPOSITORY_GOVERNANCE_SPEC_PASS")
        print(json.dumps({"target_branch": spec["target_branch"], "required_status_context": spec["required_status_context"], "ruleset_name": spec["ruleset"]["name"]}, indent=2, sort_keys=True))
        return 0
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if not token or not repo:
        raise GovernanceError("live mode requires GITHUB_TOKEN and GITHUB_REPOSITORY")
    proof = _validate_live(spec, token, repo)
    print("REPOSITORY_GOVERNANCE_LIVE_PASS")
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GovernanceError as exc:
        print(f"REPOSITORY_GOVERNANCE_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
