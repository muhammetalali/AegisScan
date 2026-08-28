from __future__ import annotations

import os
from typing import Any

from . import itsm_sandbox
from .itsm_configuration import validate_itsm_configuration


def _servicenow_idempotency_field() -> str:
    return (os.getenv("SERVICENOW_IDEMPOTENCY_FIELD") or "correlation_id").strip() or "correlation_id"


def _capabilities(provider: str) -> dict[str, bool]:
    if provider == "jira":
        return {
            "create_ticket": True,
            "reconcile_by_idempotency": True,
            "lifecycle_sync": True,
        }
    return {
        "create_ticket": True,
        "reconcile_by_idempotency": bool(_servicenow_idempotency_field()),
        "lifecycle_sync": True,
    }


async def provider_capability(provider: str) -> dict[str, Any]:
    provider = provider.strip().lower()
    if provider not in {"jira", "servicenow"}:
        return {"provider": provider, "status": "unsupported", "capabilities": {}}

    if itsm_sandbox.enabled():
        return {
            "provider": provider,
            "status": "ready",
            "mode": "sandbox",
            "external": False,
            "readiness_basis": "sandbox",
            "capabilities": itsm_sandbox.capabilities(provider),
        }

    state = validate_itsm_configuration().get(provider)
    if state is None:
        return {"provider": provider, "status": "unsupported", "capabilities": {}}
    if not state.enabled:
        return {"provider": provider, "status": "not_configured", "capabilities": {}}
    if not state.valid:
        return {
            "provider": provider,
            "status": "invalid_configuration",
            "errors": list(state.errors),
            "capabilities": {},
        }

    return {
        "provider": provider,
        "status": "ready",
        "mode": "real",
        "external": True,
        "readiness_basis": "configuration",
        "capabilities": _capabilities(provider),
        "warnings": [],
    }


async def all_provider_capabilities() -> list[dict[str, Any]]:
    return [await provider_capability(provider) for provider in ("jira", "servicenow")]
