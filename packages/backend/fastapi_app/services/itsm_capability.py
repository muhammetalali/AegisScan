from __future__ import annotations

import os
from typing import Any

from .itsm_configuration import validate_itsm_configuration
from .itsm_provider_health import check_provider


async def provider_capability(provider: str) -> dict[str, Any]:
    provider = provider.strip().lower()
    configs = validate_itsm_configuration()
    state = configs.get(provider)
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

    health = await check_provider(provider)
    if health.get("status") != "healthy":
        return {
            "provider": provider,
            "status": "unhealthy",
            "health": health,
            "capabilities": {},
        }

    if provider == "jira":
        capabilities = {
            "create_issue": True,
            "search_by_idempotency": True,
            "transition_issue": True,
            "read_issue": True,
            "update_issue": True,
            "comments": True,
        }
    else:
        capabilities = {
            "create_incident": True,
            "search_by_idempotency": bool(os.getenv("SERVICENOW_IDEMPOTENCY_FIELD")),
            "transition_incident": True,
            "read_incident": True,
            "update_incident": True,
            "comments": True,
        }

    return {"provider": provider, "status": "ready", "health": health, "capabilities": capabilities}


async def all_provider_capabilities() -> list[dict[str, Any]]:
    return [await provider_capability(provider) for provider in ("jira", "servicenow")]
