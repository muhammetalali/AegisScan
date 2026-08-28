from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

# Resolve the backend package from the script location so the runner works
# regardless of the caller's current working directory.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

from fastapi_app.services.itsm_remediation_resilient import create_case


for candidate in (
    ROOT / ".env",
    ROOT.parent / "platform" / ".env",
    ROOT.parent.parent / ".env",
):
    if candidate.exists():
        load_dotenv(candidate, override=False)


async def main() -> int:
    if os.getenv("AEGIS_ITSM_E2E_ENABLE", "0").lower() not in {"1", "true", "yes"}:
        print("Set AEGIS_ITSM_E2E_ENABLE=1 to allow real external ticket creation.")
        return 2

    actor = os.getenv("AEGIS_ITSM_E2E_ACTOR", "e2e-runner")
    owner = os.getenv("AEGIS_ITSM_E2E_OWNER", "security-engineering")
    key = os.getenv("AEGIS_ITSM_E2E_IDEMPOTENCY_KEY") or f"aegis-e2e-{uuid4().hex}"
    title = os.getenv("AEGIS_ITSM_E2E_TITLE", "[AegisScan E2E] Remediation integration test")
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
    evidence = [{"id": "e2e-evidence-1", "type": "synthetic-contract", "source": "AegisScan E2E"}]

    print(f"idempotency_key={key}")
    print("Creating first real case against Jira + ServiceNow...")
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
            raise RuntimeError(f"{provider} did not return an external ticket: {item}")
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

    print("PASS: same AegisScan action and same external Jira/ServiceNow IDs were returned on retry.")
    print(f"jira={first_map['jira']}")
    print(f"servicenow={first_map['servicenow']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(130)
