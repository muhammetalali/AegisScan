#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from fastapi_app.services.kali_semgrep_provider import (
    KaliSemgrepProviderError,
    semgrep_provider_decision,
)
from fastapi_app.services.semgrep_execution_provider import run_semgrep_with_provider
from fastapi_app.services.semgrep_semantic_parity import compare_semgrep_semantics
from fastapi_app.tasks.advanced_scans import _semgrep_findings

SOURCE = "/workspace/source"
ARTIFACTS = Path("/artifacts")


def _selected_and_holdback() -> tuple[str, str]:
    selected = holdback = None
    for index in range(10000):
        key = f"semgrep-canary-{index}"
        decision = semgrep_provider_decision(routing_key=key)
        if decision.selected_provider == "kali" and selected is None:
            selected = key
        if decision.selected_provider == "legacy" and holdback is None:
            holdback = key
        if selected and holdback:
            return selected, holdback
    raise AssertionError("bounded canary did not produce both selected and holdback cohorts")


def _run(key: str, ref: str):
    return run_semgrep_with_provider(
        source=SOURCE,
        timeout_seconds=120,
        routing_key=key,
        execution_ref=ref,
        authorization_ref="auth-m4",
        scope_ref="project:m4:asset:code",
        state_getter=lambda: "running",
    )


def cohorts() -> None:
    selected, holdback = _selected_and_holdback()
    legacy = _run(holdback, "semgrep-m4-holdback")
    candidate = _run(selected, "semgrep-m4-selected")
    assert legacy.routing["selected_provider"] == "legacy", legacy.routing
    assert candidate.routing["selected_provider"] == "kali", candidate.routing
    assert candidate.runtime["provider"] == "aegis-kali-code", candidate.runtime
    assert candidate.runtime["linux_privilege"]["allowed_capabilities"] == [], candidate.runtime
    assert legacy.exit_code == candidate.exit_code, (legacy.exit_code, candidate.exit_code)

    comparison = compare_semgrep_semantics(legacy.stdout, candidate.stdout)
    assert comparison["equivalent"] is True, comparison
    assert comparison["legacy"]["finding_count"] == 1, comparison
    assert comparison["candidate"]["finding_count"] == 1, comparison

    lf = _semgrep_findings(legacy.stdout)
    cf = _semgrep_findings(candidate.stdout)
    assert len(lf) == len(cf) == 1, (lf, cf)
    assert lf[0]["path"] == cf[0]["path"] == "/workspace/source/app.py", (lf, cf)
    assert lf[0]["check_id"] == cf[0]["check_id"] == "aegis.semgrep.parity.eval", (lf, cf)

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "holdback.json").write_text(legacy.stdout, encoding="utf-8")
    (ARTIFACTS / "selected.json").write_text(candidate.stdout, encoding="utf-8")
    (ARTIFACTS / "semantic-parity.json").write_text(
        json.dumps(comparison, sort_keys=True, indent=2), encoding="utf-8"
    )
    (ARTIFACTS / "cohorts.json").write_text(
        json.dumps(
            {
                "selected_key": selected,
                "holdback_key": holdback,
                "selected_routing": candidate.routing,
                "holdback_routing": legacy.routing,
                "selected_runtime": candidate.runtime,
            },
            sort_keys=True,
            indent=2,
        ),
        encoding="utf-8",
    )
    workspace = Path("/var/lib/aegis-semgrep")
    assert list(workspace.iterdir()) == [], list(workspace.iterdir())


def zero_rollback() -> None:
    result = _run("rollback-zero", "semgrep-m4-zero")
    assert result.routing["selected_provider"] == "legacy", result.routing
    assert result.routing["reason"] == "canary-rollback-zero", result.routing


def selected_key() -> None:
    selected, _ = _selected_and_holdback()
    print(selected)


def outage() -> None:
    import fastapi_app.services.semgrep_execution_provider as provider

    key = os.environ["SELECTED_KEY"]

    def _forbidden(*args, **kwargs):
        raise AssertionError("legacy fallback attempted during selected provider outage")

    provider.run_semgrep = _forbidden
    try:
        provider.run_semgrep_with_provider(
            source=SOURCE,
            timeout_seconds=10,
            routing_key=key,
            execution_ref="semgrep-m4-outage",
            authorization_ref="auth-m4",
            scope_ref="project:m4:asset:code",
            state_getter=lambda: "running",
        )
    except KaliSemgrepProviderError:
        return
    raise AssertionError("selected Kali outage did not fail closed")


def main() -> int:
    actions = {
        "cohorts": cohorts,
        "zero": zero_rollback,
        "selected-key": selected_key,
        "outage": outage,
    }
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action not in actions:
        raise SystemExit(f"usage: {sys.argv[0]} <{'|'.join(actions)}>")
    actions[action]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
