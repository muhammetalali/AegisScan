#!/usr/bin/env python3
"""Apply and verify the AegisScan repository ruleset using an admin-scoped token."""

from __future__ import annotations

import argparse
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
MANDATORY_RULE_TYPES = {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}


class RulesetAdminError(RuntimeError):
    pass


def _api_json(method: str, path: str, token: str, payload: dict[str, Any] | None = None) -> Any:
    url = path if path.startswith("https://") else f"{API_ROOT}{path}"
    body = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AegisScan-repository-ruleset-admin",
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RulesetAdminError(f"GitHub API {method} {url} failed: {exc.code}: {detail[:800]}") from exc
    except urllib.error.URLError as exc:
        raise RulesetAdminError(f"GitHub API {method} {url} failed: {exc}") from exc


def _load_spec(path: Path) -> dict[str, Any]:
    spec = json.loads(path.read_text(encoding="utf-8"))
    if spec.get("schema_version") != 1:
        raise RulesetAdminError("unsupported schema_version")
    if spec.get("target_branch") != "main":
        raise RulesetAdminError("ruleset admin is intentionally restricted to main")
    ruleset = spec.get("ruleset")
    if not isinstance(ruleset, dict):
        raise RulesetAdminError("ruleset must be an object")
    if ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
        raise RulesetAdminError("ruleset must actively target branches")
    if ruleset.get("bypass_actors") != []:
        raise RulesetAdminError("bypass_actors must be empty")
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        raise RulesetAdminError("rules must be a list")
    by_type = {rule.get("type"): rule for rule in rules if isinstance(rule, dict)}
    missing = sorted(MANDATORY_RULE_TYPES - set(by_type))
    if missing:
        raise RulesetAdminError(f"missing mandatory rule types: {missing}")
    context = spec.get("required_status_context")
    contexts = {
        item.get("context")
        for item in (by_type["required_status_checks"].get("parameters") or {}).get("required_status_checks", [])
        if isinstance(item, dict)
    }
    if context not in contexts:
        raise RulesetAdminError(f"required status context is not enforced: {context!r}")
    return spec


def _ruleset_payload(spec: dict[str, Any]) -> dict[str, Any]:
    ruleset = spec["ruleset"]
    return {
        "name": ruleset["name"],
        "target": ruleset["target"],
        "enforcement": ruleset["enforcement"],
        "bypass_actors": ruleset["bypass_actors"],
        "conditions": ruleset["conditions"],
        "rules": ruleset["rules"],
    }


def _find_named_ruleset(repo: str, token: str, name: str) -> dict[str, Any] | None:
    rulesets = _api_json("GET", f"/repos/{repo}/rulesets?includes_parents=false", token)
    if not isinstance(rulesets, list):
        raise RulesetAdminError("GitHub returned an unexpected ruleset list")
    matches = [item for item in rulesets if isinstance(item, dict) and item.get("name") == name]
    if len(matches) > 1:
        ids = [item.get("id") for item in matches]
        raise RulesetAdminError(f"duplicate named rulesets detected for {name!r}: {ids}")
    return matches[0] if matches else None


def _assert_live_rules(repo: str, token: str, spec: dict[str, Any]) -> dict[str, Any]:
    name = spec["ruleset"]["name"]
    current = _find_named_ruleset(repo, token, name)
    if current is None:
        raise RulesetAdminError(f"ruleset {name!r} is not present after apply")
    ruleset_id = current.get("id")
    if not isinstance(ruleset_id, int):
        raise RulesetAdminError("ruleset id is missing")
    detail = _api_json("GET", f"/repos/{repo}/rulesets/{ruleset_id}", token)
    if not isinstance(detail, dict):
        raise RulesetAdminError("GitHub returned an unexpected ruleset detail")
    if detail.get("name") != name or detail.get("target") != "branch" or detail.get("enforcement") != "active":
        raise RulesetAdminError("named ruleset is not active with the expected identity")
    if detail.get("bypass_actors") not in ([], None):
        raise RulesetAdminError("named ruleset contains bypass actors")

    branch = spec["target_branch"]
    branch_payload = _api_json("GET", f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}", token)
    if not isinstance(branch_payload, dict) or branch_payload.get("protected") is not True:
        raise RulesetAdminError(f"branch {branch!r} is not protected after apply")
    effective = _api_json("GET", f"/repos/{repo}/rules/branches/{urllib.parse.quote(branch, safe='')}", token)
    if not isinstance(effective, list):
        raise RulesetAdminError("GitHub returned an unexpected effective-rules response")
    by_type: dict[str, list[dict[str, Any]]] = {}
    for rule in effective:
        if isinstance(rule, dict) and isinstance(rule.get("type"), str):
            by_type.setdefault(rule["type"], []).append(rule)
    missing = sorted(rule_type for rule_type in MANDATORY_RULE_TYPES if not by_type.get(rule_type))
    if missing:
        raise RulesetAdminError(f"effective main rules are missing: {missing}")
    context = spec["required_status_context"]
    status_ok = False
    strict_ok = False
    for rule in by_type["required_status_checks"]:
        parameters = rule.get("parameters") or {}
        strict_ok = strict_ok or parameters.get("strict_required_status_checks_policy") is True
        contexts = {
            item.get("context")
            for item in parameters.get("required_status_checks", [])
            if isinstance(item, dict)
        }
        status_ok = status_ok or context in contexts
    if not status_ok or not strict_ok:
        raise RulesetAdminError("effective required-status-check rule is incomplete")
    if not any((rule.get("parameters") or {}).get("required_review_thread_resolution") is True for rule in by_type["pull_request"]):
        raise RulesetAdminError("effective pull-request rule does not require review-thread resolution")
    return {
        "repository": repo,
        "ruleset_id": ruleset_id,
        "ruleset_name": name,
        "branch": branch,
        "branch_sha": (branch_payload.get("commit") or {}).get("sha"),
        "protected": True,
        "active_rule_types": sorted(by_type),
        "required_status_context": context,
    }


def _apply(repo: str, token: str, spec: dict[str, Any]) -> dict[str, Any]:
    payload = _ruleset_payload(spec)
    current = _find_named_ruleset(repo, token, payload["name"])
    if current is None:
        operation = "created"
        _api_json("POST", f"/repos/{repo}/rulesets", token, payload)
    else:
        ruleset_id = current.get("id")
        if not isinstance(ruleset_id, int):
            raise RulesetAdminError("existing ruleset id is missing")
        operation = "updated"
        _api_json("PUT", f"/repos/{repo}/rulesets/{ruleset_id}", token, payload)
    proof = _assert_live_rules(repo, token, spec)
    proof["operation"] = operation
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("spec", type=Path)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--mode", choices=("plan", "apply", "verify"), required=True)
    parser.add_argument("--token-env", default="AEGIS_GITHUB_ADMIN_TOKEN")
    args = parser.parse_args()

    spec = _load_spec(args.spec)
    if args.mode == "plan":
        print("REPOSITORY_RULESET_ADMIN_PLAN_PASS")
        print(json.dumps(_ruleset_payload(spec), indent=2, sort_keys=True))
        return 0

    repo = args.repo.strip()
    if not REPO_RE.fullmatch(repo):
        raise RulesetAdminError("--repo must be owner/name")
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        raise RulesetAdminError(f"{args.mode} mode requires admin token in environment variable {args.token_env}")
    proof = _apply(repo, token, spec) if args.mode == "apply" else _assert_live_rules(repo, token, spec)
    print("REPOSITORY_RULESET_ADMIN_PASS")
    print(json.dumps(proof, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RulesetAdminError as exc:
        print(f"REPOSITORY_RULESET_ADMIN_FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
