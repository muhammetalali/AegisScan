from __future__ import annotations

import os
from typing import Any

from . import itsm_sandbox
from .itsm_configuration import validate_itsm_configuration


def _servicenow_idempotency_field() -> str:
    return (os.getenv("SERVICENOW_IDEMPOTENCY_FIELD") or "correlation_id").strip() or "correlation_id"


def _operations(provider: str) -> dict[str, dict[str, Any]]:
    reconciliation = provider == "jira" or bool(_servicenow_idempotency_field())
    return {
        "health_check": {"supported": True, "requires_live_provider": True},
        "create": {"supported": True, "requires_live_provider": True},
        "reconcile": {"supported": reconciliation, "requires_live_provider": True},
        "transition": {"supported": True, "requires_live_provider": True},
        "verify": {"supported": True, "requires_live_provider": True},
    }


def _capabilities(provider: str) -> dict[str, bool]:
    ops = _operations(provider)
    return {
        "create_ticket": ops["create"]["supported"],
        "reconcile_by_idempotency": ops["reconcile"]["supported"],
        "lifecycle_sync": ops["transition"]["supported"],
        "verification_sync": ops["verify"]["supported"],
    }


async def provider_capability(provider: str) -> dict[str, Any]:
    provider = provider.strip().lower()
    if provider not in {"jira", "servicenow"}:
        return {"provider": provider, "status": "unsupported", "capabilities": {}, "operations": {}}

    operations = _operations(provider)
    if itsm_sandbox.enabled():
        return {"provider": provider, "status": "ready", "mode": "sandbox", "external": False, "readiness_basis": "sandbox", "capabilities": itsm_sandbox.capabilities(provider), "operations": operations}

    state = validate_itsm_configuration().get(provider)
    if state is None:
        return {"provider": provider, "status": "unsupported", "capabilities": {}, "operations": {}}
    if not state.enabled:
        return {"provider": provider, "status": "not_configured", "capabilities": {}, "operations": operations}
    if not state.valid:
        return {"provider": provider, "status": "invalid_configuration", "errors": list(state.errors), "capabilities": {}, "operations": operations}

    return {"provider": provider, "status": "ready", "mode": "real", "external": True, "readiness_basis": "configuration", "capabilities": _capabilities(provider), "operations": operations, "warnings": []}


async def all_provider_capabilities() -> list[dict[str, Any]]:
    return [await provider_capability(provider) for provider in ("jira", "servicenow")]
