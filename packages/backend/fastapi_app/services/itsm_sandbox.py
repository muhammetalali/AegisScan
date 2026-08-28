from __future__ import annotations

import hashlib
import os
from typing import Any


def enabled() -> bool:
    return os.getenv("AEGIS_ITSM_MODE", "real").strip().lower() == "sandbox"


def _external_id(provider: str, idempotency_key: str) -> str:
    digest = hashlib.sha256(f"{provider}:{idempotency_key}".encode()).hexdigest()[:12]
    prefix = "SANDBOX-JIRA" if provider == "jira" else "SANDBOX-SNOW"
    return f"{prefix}-{digest}"


def capabilities(provider: str) -> dict[str, bool]:
    if provider == "jira":
        return {"create_issue": True, "search_by_idempotency": True, "transition_issue": True, "read_issue": True, "update_issue": True, "comments": True}
    return {"create_incident": True, "search_by_idempotency": True, "transition_incident": True, "read_incident": True, "update_incident": True, "comments": True}


def health(provider: str) -> dict[str, Any]:
    return {"provider": provider, "status": "healthy", "transport": "sandbox", "external": False, "latency_ms": 0.0}


def create(*, provider: str, decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idempotency_key: str) -> dict[str, Any]:
    external_id = _external_id(provider, idempotency_key)
    return {
        "status": "created",
        "provider": provider,
        "external_id": external_id,
        "external_url": f"sandbox://{provider}/{external_id}",
        "response": {
            "mode": "sandbox",
            "external": False,
            "idempotency_key": idempotency_key,
            "action_id": action["actionId"],
            "decision_id": decision.get("decisionId"),
            "evidence_count": len(evidence),
            "ticket": {"id": external_id, "state": "created"},
        },
    }
