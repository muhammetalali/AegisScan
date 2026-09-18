#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
import django

django.setup()

from fastapi_app.services import semgrep_execution_provider as provider_module
from fastapi_app.services.kali_semgrep_provider import (
    KaliSemgrepProviderError,
    semgrep_provider_decision,
)
from fastapi_app.services.semgrep_execution_provider import run_semgrep_with_provider
from fastapi_app.services.semgrep_semantic_parity import compare_semgrep_semantics
from fastapi_app.tasks.advanced_scans import _semgrep_findings

SOURCE = "/workspace/source"
ARTIFACTS = Path("/artifacts")


def _run(ref: str, key: str):
    return run_semgrep_with_provider(
        source=SOURCE,
        timeout_seconds=120,
        routing_key=key,
        execution_ref=ref,
        authorization_ref="auth-m5",
        scope_ref="project:m5:asset:code",
        state_getter=lambda: "running",
    )


def default_kali() -> None:
    for key in ("semgrep-m5-default-a", "semgrep-m5-default-b"):
        decision = semgrep_provider_decision(routing_key=key)
        assert decision.mode == "default-kali", decision
        assert decision.selected_provider == "kali", decision
        assert decision.parity_approved is True, decision
        assert decision.canary_bps == 0, decision
        assert decision.bucket is None, decision
        assert decision.routing_key_digest == "", decision
        assert decision.reason == "default-kali-parity-approved", decision

    result = _run("semgrep-m5-default", "semgrep-m5-default-a")
    assert result.routing["selected_provider"] == "kali", result.routing
    assert result.runtime["provider"] == "aegis-kali-code", result.runtime
    assert result.runtime["linux_privilege"]["allowed_capabilities"] == [], result.runtime
    assert result.exit_code in {0, 1}, (result.exit_code, result.stderr)
    payload = json.loads(result.stdout)
    assert len(payload.get("results", [])) == 1, payload
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "default-kali.json").write_text(result.stdout, encoding="utf-8")
    (ARTIFACTS / "default-kali-result.json").write_text(
        json.dumps({"routing": result.routing, "runtime": result.runtime}, sort_keys=True, indent=2),
        encoding="utf-8",
    )


def legacy_reference() -> None:
    result = _run("semgrep-m5-legacy-reference", "legacy-reference")
    assert result.routing["mode"] == "legacy", result.routing
    assert result.routing["selected_provider"] == "legacy", result.routing
    assert result.runtime["provider"] == "legacy-native-worker", result.runtime
    assert result.exit_code in {0, 1}, (result.exit_code, result.stderr)
    payload = json.loads(result.stdout)
    assert len(payload.get("results", [])) == 1, payload
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "legacy-reference.json").write_text(result.stdout, encoding="utf-8")
    (ARTIFACTS / "legacy-reference-result.json").write_text(
        json.dumps({"routing": result.routing, "runtime": result.runtime}, sort_keys=True, indent=2),
        encoding="utf-8",
    )


def compare() -> None:
    legacy = (ARTIFACTS / "legacy-reference.json").read_text(encoding="utf-8")
    candidate = (ARTIFACTS / "default-kali.json").read_text(encoding="utf-8")
    comparison = compare_semgrep_semantics(legacy, candidate)
    assert comparison["equivalent"] is True, comparison
    assert comparison["legacy"]["finding_count"] == 1, comparison
    assert comparison["candidate"]["finding_count"] == 1, comparison

    lf = _semgrep_findings(legacy)
    cf = _semgrep_findings(candidate)
    assert len(lf) == len(cf) == 1, (lf, cf)
    for field in ("check_id", "message", "severity", "path", "line"):
        assert lf[0][field] == cf[0][field], (field, lf, cf)
    assert lf[0]["path"] == cf[0]["path"] == "/workspace/source/app.py", (lf, cf)
    assert lf[0]["check_id"].endswith("aegis.semgrep.parity.eval"), (lf, cf)

    (ARTIFACTS / "default-kali-semantic-parity.json").write_text(
        json.dumps(comparison, sort_keys=True, indent=2), encoding="utf-8"
    )


def outage() -> None:
    def _forbidden(*args, **kwargs):
        raise AssertionError("silent legacy fallback attempted during default-kali outage")

    provider_module.run_semgrep = _forbidden
    try:
        provider_module.run_semgrep_with_provider(
            source=SOURCE,
            timeout_seconds=10,
            routing_key="semgrep-m5-outage",
            execution_ref="semgrep-m5-outage",
            authorization_ref="auth-m5",
            scope_ref="project:m5:asset:code",
            state_getter=lambda: "running",
        )
    except KaliSemgrepProviderError as exc:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS / "default-kali-outage.json").write_text(
            json.dumps({"fail_closed": True, "error": str(exc)}, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        return
    raise AssertionError("default-kali provider outage did not fail closed")


def rollback() -> None:
    result = _run("semgrep-m5-explicit-rollback", "explicit-rollback")
    assert result.routing["mode"] == "legacy", result.routing
    assert result.routing["selected_provider"] == "legacy", result.routing
    assert result.runtime["provider"] == "legacy-native-worker", result.runtime
    assert result.exit_code in {0, 1}, (result.exit_code, result.stderr)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "explicit-legacy-rollback.json").write_text(
        json.dumps({"routing": result.routing, "runtime": result.runtime}, sort_keys=True, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    actions = {
        "default": default_kali,
        "legacy": legacy_reference,
        "compare": compare,
        "outage": outage,
        "rollback": rollback,
    }
    action = sys.argv[1] if len(sys.argv) > 1 else ""
    if action not in actions:
        raise SystemExit(f"usage: {sys.argv[0]} <{'|'.join(actions)}>")
    actions[action]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
