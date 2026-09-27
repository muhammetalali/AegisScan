#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API_ROOT = "https://api.github.com"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class RequiredCIGateError(RuntimeError):
    pass


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RequiredCIGateError(f"required environment variable is missing: {name}")
    return value


def _api_json(
    path: str,
    token: str,
    *,
    max_attempts: int = 5,
    retry_base_seconds: float = 1.0,
) -> Any:
    if max_attempts < 1:
        raise RequiredCIGateError("GitHub API max_attempts must be at least 1")
    if retry_base_seconds < 0:
        raise RequiredCIGateError("GitHub API retry_base_seconds must be non-negative")

    request = urllib.request.Request(
        f"{API_ROOT}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AegisScan-live-ci-barrier",
        },
    )
    transient_http = {429, 500, 502, 503, 504}
    transient_transport = (
        http.client.IncompleteRead,
        http.client.RemoteDisconnected,
        TimeoutError,
        socket.timeout,
        urllib.error.URLError,
    )
    last_error: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in transient_http:
                body = exc.read().decode("utf-8", errors="replace")
                raise RequiredCIGateError(
                    f"GitHub API request failed: HTTP {exc.code}: {body[:500]}"
                ) from exc
            last_error = exc
            retry_after = str(exc.headers.get("Retry-After") or "").strip()
            if retry_after.isdigit():
                delay = min(float(retry_after), 30.0)
            else:
                delay = min(retry_base_seconds * (2 ** (attempt - 1)), 8.0)
        except transient_transport as exc:
            last_error = exc
            delay = min(retry_base_seconds * (2 ** (attempt - 1)), 8.0)

        if attempt == max_attempts:
            break
        time.sleep(delay)

    raise RequiredCIGateError(
        f"GitHub API request failed after {max_attempts} attempts: {last_error}"
    ) from last_error


def _live_branch_sha(repo: str, branch: str, token: str) -> str:
    encoded = urllib.parse.quote(branch, safe="")
    payload = _api_json(f"/repos/{repo}/branches/{encoded}", token)
    if not isinstance(payload, dict):
        raise RequiredCIGateError("GitHub branch response is not an object")
    sha = str((payload.get("commit") or {}).get("sha") or "")
    if not SHA_RE.fullmatch(sha):
        raise RequiredCIGateError(f"live branch {branch!r} returned an invalid SHA")
    return sha


def _select_run(
    payload: dict[str, Any],
    *,
    sha: str,
    branch: str,
    workflow_name: str,
    event: str,
) -> dict[str, Any] | None:
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise RequiredCIGateError("GitHub Actions response has no workflow_runs list")
    candidates = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("name") == workflow_name
        and run.get("head_sha") == sha
        and run.get("head_branch") == branch
        and run.get("event") == event
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda run: (
            int(run.get("run_attempt") or 0),
            int(run.get("id") or 0),
        ),
        reverse=True,
    )
    return candidates[0]


def wait_for_required_ci(
    *,
    repo: str,
    token: str,
    sha: str,
    branch: str,
    workflow_name: str,
    event: str,
    timeout_seconds: int,
    poll_seconds: int,
) -> dict[str, Any]:
    if not SHA_RE.fullmatch(sha):
        raise RequiredCIGateError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if not repo or "/" not in repo:
        raise RequiredCIGateError("repository must use owner/name form")
    if not branch:
        raise RequiredCIGateError("branch must be non-empty")
    if not workflow_name:
        raise RequiredCIGateError("workflow name must be non-empty")
    if event not in {"push", "workflow_dispatch"}:
        raise RequiredCIGateError("event must be push or workflow_dispatch")
    if timeout_seconds <= 0 or poll_seconds <= 0 or timeout_seconds < poll_seconds:
        raise RequiredCIGateError("timeout/poll values are invalid")

    deadline = time.monotonic() + timeout_seconds
    last_summary: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        live_sha = _live_branch_sha(repo, branch, token)
        if live_sha != sha:
            raise RequiredCIGateError(
                f"live branch {branch} moved while waiting for CI: expected {sha}, actual {live_sha}"
            )
        query = urllib.parse.urlencode(
            {
                "head_sha": sha,
                "event": event,
                "per_page": 100,
            }
        )
        payload = _api_json(f"/repos/{repo}/actions/runs?{query}", token)
        if not isinstance(payload, dict):
            raise RequiredCIGateError("GitHub Actions response is not an object")
        run = _select_run(
            payload,
            sha=sha,
            branch=branch,
            workflow_name=workflow_name,
            event=event,
        )
        if run is None:
            last_summary = {"state": "missing"}
        else:
            last_summary = {
                "state": "observed",
                "id": run.get("id"),
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
                "run_attempt": run.get("run_attempt"),
            }
            if run.get("status") == "completed":
                if run.get("conclusion") == "success":
                    return {
                        "schema": "aegisscan.required-ci-live-barrier.v1",
                        "release_sha": sha,
                        "workflow": workflow_name,
                        "event": event,
                        "run_id": run.get("id"),
                        "run_attempt": run.get("run_attempt"),
                        "status": "success",
                    }
                raise RequiredCIGateError(
                    f"{workflow_name} completed without success for exact SHA {sha}: "
                    f"{run.get('conclusion')!r}"
                )
        time.sleep(poll_seconds)

    raise RequiredCIGateError(
        f"timed out waiting for {workflow_name} on exact SHA {sha}; last={last_summary}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Wait fail-closed for exact-SHA Required CI Governance before live execution"
    )
    parser.add_argument("--sha", required=True)
    parser.add_argument("--branch", default="main")
    parser.add_argument("--workflow-name", default="Required CI Governance")
    parser.add_argument("--event", default="push")
    parser.add_argument("--timeout-seconds", type=int, default=4500)
    parser.add_argument("--poll-seconds", type=int, default=15)
    args = parser.parse_args()

    try:
        result = wait_for_required_ci(
            repo=_required_env("GITHUB_REPOSITORY"),
            token=_required_env("GITHUB_TOKEN"),
            sha=args.sha.strip().lower(),
            branch=args.branch.strip(),
            workflow_name=args.workflow_name.strip(),
            event=args.event.strip(),
            timeout_seconds=args.timeout_seconds,
            poll_seconds=args.poll_seconds,
        )
    except RequiredCIGateError as exc:
        print(f"REQUIRED_CI_LIVE_BARRIER_FAIL: {exc}", file=sys.stderr)
        return 1
    print("REQUIRED_CI_LIVE_BARRIER_PASS")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
