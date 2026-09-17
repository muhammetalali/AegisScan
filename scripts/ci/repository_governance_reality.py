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
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AegisScan-repository-governance-reality",
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


def _rules_by_type(rules: Any, source: str) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(rules, list):
        raise GovernanceError(f"GitHub returned an unexpected {source} rules response")
    by_type: dict[str, list[dict[str, Any]]] = {}
    for rule in rules:
        if isinstance(rule, dict) and isinstance(rule.get("type"), str):
            by_type.setdefault(rule["type"], []).append(rule)
    missing = sorted(rule_type for rule_type in REQUIRED_RULE_TYPES if not by_type.get(rule_type))
    if missing:
        raise GovernanceError(f"{source} rules are missing mandatory rule types: {missing}")
    return by_type


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
    if not isinstance(ruleset.get("name"), str) or not ruleset["name"].strip():
        raise GovernanceError("ruleset must define a non-empty name")
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
    contexts = {
        item.get("context")
        for item in status_parameters.get("required_status_checks") or []
        if isinstance(item, dict)
    }
    if context not in contexts:
        raise GovernanceError(f"ruleset must require status context: {context}")
    return spec


def _select_live_ruleset(spec: dict[str, Any], token: str, repo: str) -> dict[str, Any]:
    expected = spec["ruleset"]
    summaries = _api_json(f"/repos/{repo}/rulesets", token)
    if not isinstance(summaries, list):
        raise GovernanceError("GitHub returned an unexpected repository-rulesets response")

    matches = [
        item
        for item in summaries
        if isinstance(item, dict)
        and item.get("name") == expected["name"]
        and item.get("target") == expected["target"]
    ]
    if len(matches) != 1:
        raise GovernanceError(
            f"expected exactly one ruleset named {expected['name']!r}; found {len(matches)}"
        )
    summary = matches[0]
    if summary.get("enforcement") != "active":
        raise GovernanceError("named main ruleset is not active")
    ruleset_id = summary.get("id")
    if not isinstance(ruleset_id, int):
        raise GovernanceError("named main ruleset has no numeric id")

    detail = _api_json(f"/repos/{repo}/rulesets/{ruleset_id}", token)
    if not isinstance(detail, dict):
        raise GovernanceError("GitHub returned an unexpected repository-ruleset detail response")
    if detail.get("name") != expected["name"]:
        raise GovernanceError("live ruleset name changed between list and detail reads")
    if detail.get("target") != "branch" or detail.get("enforcement") != "active":
        raise GovernanceError("live main ruleset is not an active branch ruleset")

    bypass_actors = detail.get("bypass_actors")
    if not isinstance(bypass_actors, list):
        raise GovernanceError("live main ruleset did not expose bypass_actors for verification")
    if bypass_actors:
        raise GovernanceError(f"live main ruleset has forbidden bypass actors: {bypass_actors}")

    conditions = detail.get("conditions") or {}
    live_includes = ((conditions.get("ref_name") or {}).get("include") or [])
    if "~DEFAULT_BRANCH" not in live_includes and "refs/heads/main" not in live_includes:
        raise GovernanceError("live named ruleset does not target the default/main branch")

    spec_rules = {item.get("type"): item for item in expected.get("rules") or [] if isinstance(item, dict)}
    live_by_type = _rules_by_type(detail.get("rules"), "named live ruleset")

    expected_pr = (spec_rules["pull_request"].get("parameters") or {})
    expected_approvals = int(expected_pr["required_approving_review_count"])
    live_pr_match = any(
        int((rule.get("parameters") or {}).get("required_approving_review_count", -1)) == expected_approvals
        and (rule.get("parameters") or {}).get("required_review_thread_resolution") is True
        for rule in live_by_type["pull_request"]
    )
    if not live_pr_match:
        raise GovernanceError(
            "live named ruleset pull-request parameters do not match the governed approval/thread policy"
        )

    required_context = spec["required_status_context"]
    live_status_match = False
    for rule in live_by_type["required_status_checks"]:
        parameters = rule.get("parameters") or {}
        contexts = {
            item.get("context")
            for item in parameters.get("required_status_checks") or []
            if isinstance(item, dict)
        }
        if (
            parameters.get("strict_required_status_checks_policy") is True
            and required_context in contexts
        ):
            live_status_match = True
            break
    if not live_status_match:
        raise GovernanceError("live named ruleset does not enforce the strict governed status context")

    return detail


def _validate_live(spec: dict[str, Any], token: str, repo: str) -> dict[str, Any]:
    branch = spec["target_branch"]
    branch_payload = _api_json(f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}", token)
    if branch_payload.get("protected") is not True:
        raise GovernanceError(f"branch {branch} is not protected")

    live_ruleset = _select_live_ruleset(spec, token, repo)

    effective_rules = _api_json(
        f"/repos/{repo}/rules/branches/{urllib.parse.quote(branch, safe='')}", token
    )
    by_type = _rules_by_type(effective_rules, "active main")
    if not any(
        (rule.get("parameters") or {}).get("required_review_thread_resolution") is True
        for rule in by_type["pull_request"]
    ):
        raise GovernanceError("active pull-request rules do not require review-thread resolution")

    required_context = spec["required_status_context"]
    status_rule_ok = False
    strict_ok = False
    for rule in by_type["required_status_checks"]:
        parameters = rule.get("parameters") or {}
        strict_ok = strict_ok or parameters.get("strict_required_status_checks_policy") is True
        contexts = {
            item.get("context")
            for item in parameters.get("required_status_checks") or []
            if isinstance(item, dict)
        }
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
        "ruleset_id": live_ruleset.get("id"),
        "ruleset_name": live_ruleset.get("name"),
        "ruleset_enforcement": live_ruleset.get("enforcement"),
        "bypass_actor_count": len(live_ruleset.get("bypass_actors") or []),
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
        print(
            json.dumps(
                {
                    "target_branch": spec["target_branch"],
                    "required_status_context": spec["required_status_context"],
                    "ruleset_name": spec["ruleset"]["name"],
                    "bypass_actor_count": len(spec["ruleset"]["bypass_actors"]),
                },
                indent=2,
                sort_keys=True,
            )
        )
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
