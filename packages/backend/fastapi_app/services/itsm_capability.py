from __future__ import annotations

import os
from typing import Any

from . import itsm_sandbox
from .itsm_configuration import validate_itsm_configuration
from .itsm_provider_health import check_provider


def _capabilities(provider: str, *, servicenow_idempotency_field: bool) -> dict[str, bool]:
    if provider == "jira":
        return {"create_ticket": True, "reconcile_by_idempotency": True, "lifecycle_sync": True}
    return {
        "create_ticket": True,
        "reconcile_by_idempotency": servicenow_idempotency_field,
        "lifecycle_sync": True,
    }


async def provider_capability(provider: str) -> dict[str, Any]:
    provider = provider.strip().lower()
    if itsm_sandbox.enabled():
        if provider not in {"jira", "servicenow"}:
            return {"provider": provider, "status": "unsupported", "capabilities": {}}
        return {
            "provider": provider,
            "status": "ready",
            "mode": "sandbox",
            "external": False,
            "health": await check_provider(provider),
            "capabilities": itsm_sandbox.capabilities(provider),
        }

    configs = validate_itsm_configuration()
    state = configs.get(provider)
    if state is None:
        return {"provider": provider, "status": "unsupported", "capabilities": {}}
    if not state.enabled:
        return {"provider": provider, "status": "not_configured", "capabilities": {}}
    if not state.valid:
        return {"provider": provider, "status": "invalid_configuration", "errors": list(state.errors), "capabilities": {}}

    health = await check_provider(provider)
    if health.get("status") != "healthy":
        return {"provider": provider, "status": "unhealthy", "health": health, "capabilities": {}}

    capabilities = _capabilities(
        provider,
        servicenow_idempotency_field=bool(provider == "servicenow" and os.getenv("SERVICENOW_IDEMPOTENCY_FIELD")),
    )
    warnings: list[str] = []
    if provider == "servicenow" and not capabilities["reconcile_by_idempotency"]:
        warnings.append("SERVICENOW_IDEMPOTENCY_FIELD is not configured; provider-side reconciliation is unavailable")
    status = "ready" if not warnings else "degraded"
    return {"provider": provider, "status": status, "health": health, "capabilities": capabilities, "warnings": warnings}


async def all_provider_capabilities() -> list[dict[str, Any]]:
    return [await provider_capability(provider) for provider in ("jira", "servicenow")]
