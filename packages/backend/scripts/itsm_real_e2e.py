from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

from fastapi_app.services.itsm_capability import provider_capability
from fastapi_app.services.itsm_configuration import validate_itsm_configuration
from fastapi_app.services.itsm_remediation_resilient import create_case

for candidate in (ROOT / ".env", ROOT.parent / "platform" / ".env", ROOT.parent.parent / ".env"):
    if candidate.exists():
        load_dotenv(candidate, override=False)


async def _validate_before_external_creation() -> None:
    mode = os.getenv("AEGIS_ITSM_MODE", "real").strip().lower()
    states = validate_itsm_configuration()
    config_errors = {
        provider: state.errors
        for provider, state in states.items()
        if state.enabled and not state.valid
    }
    if config_errors:
        details = " | ".join(
            f"{provider}: {', '.join(messages)}" for provider, messages in config_errors.items()
        )
        raise RuntimeError("ITSM startup validation failed; no tickets will be created: " + details)

    for provider in ("jira", "servicenow"):
        capability = await provider_capability(provider)
        if capability.get("status") != "ready":
            raise RuntimeError(
                f"{provider} provider capabilities are not ready: {capability.get('status')}"
            )
        print(
            f"{provider}.ready=true mode={mode} external={capability.get('external', mode == 'real')} "
            f"basis={capability.get('readiness_basis', 'sandbox' if mode == 'sandbox' else 'configuration')}"
        )


async def main() -> int:
    if os.getenv("AEGIS_ITSM_E2E_ENABLE", "0").lower() not in {"1", "true", "yes"}:
        print("Set AEGIS_ITSM_E2E_ENABLE=1 to allow E2E ticket creation.")
        return 2

    mode = os.getenv("AEGIS_ITSM_MODE", "real").strip().lower()
    if mode not in {"real", "sandbox"}:
        raise RuntimeError("AEGIS_ITSM_MODE must be 'real' or 'sandbox'")

    await _validate_before_external_creation()

    actor = os.getenv("AEGIS_ITSM_E2E_ACTOR", "e2e-runner")
    owner = os.getenv("AEGIS_ITSM_E2E_OWNER", "security-engineering")
    key = os.getenv("AEGIS_ITSM_E2E_IDEMPOTENCY_KEY") or f"aegis-e2e-{uuid4().hex}"
    title = os.getenv("AEGIS_ITSM_E2E_TITLE", f"[AegisScan {mode.upper()} E2E] Remediation integration test")
    decision_id = f"e2e-decision-{uuid4().hex[:12]}"
    decision: dict[str, Any] = {
        "decisionId": decision_id,
        "label": title,
        "title": title,
        "final_score": 91,
        "confidence": 0.97,
        "severity": "critical",
        "recommended_action": "Close the test remediation after successful integration verification.",
        "finding_id": f"e2e-finding-{uuid4().hex[:12]}",
    }
    evidence = [{"id": "e2e-evidence-1", "type": "synthetic-contract", "source": f"AegisScan {mode} E2E"}]

    print(f"mode={mode} idempotency_key={key}")
    print("Creating first Jira + ServiceNow case...")
    first = await create_case(
        decision=decision,
        owner=owner,
        actor=actor,
        idempotency_key=key,
        providers=["jira", "servicenow"],
        evidence=evidence,
        approved=False,
    )

    print(f"first.actionId={first['action']['actionId']}")
    by_provider = {item["provider"]: item for item in first["integrations"]}
    for provider in ("jira", "servicenow"):
        item = by_provider.get(provider)
        if not item or not item.get("external_id"):
            raise RuntimeError(f"{provider} did not return an integration record: {item}")
        print(f"first.{provider}.external_id={item['external_id']}")

    print("Retrying with the exact same idempotency key...")
    second = await create_case(
        decision=decision,
        owner=owner,
        actor=actor,
        idempotency_key=key,
        providers=["jira", "servicenow"],
        evidence=evidence,
        approved=False,
    )

    if second["action"]["actionId"] != first["action"]["actionId"]:
        raise AssertionError("Retry created a second AegisScan action")

    first_map = {item["provider"]: item["external_id"] for item in first["integrations"]}
    second_map = {item["provider"]: item["external_id"] for item in second["integrations"]}
    if first_map != second_map:
        raise AssertionError(f"External IDs changed on retry: first={first_map} second={second_map}")

    expected_prefix = {"jira": "SANDBOX-JIRA-", "servicenow": "SANDBOX-SNOW-"}
    if mode == "sandbox":
        for provider, prefix in expected_prefix.items():
            if not first_map[provider].startswith(prefix):
                raise AssertionError(
                    f"Sandbox provider returned a non-sandbox external ID for {provider}: {first_map[provider]}"
                )

    print(f"PASS: mode={mode}; same action and same Jira/ServiceNow IDs were returned on retry.")
    print(f"jira={first_map['jira']}")
    print(f"servicenow={first_map['servicenow']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(130)
