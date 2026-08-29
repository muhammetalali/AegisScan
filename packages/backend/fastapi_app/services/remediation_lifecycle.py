from __future__ import annotations

from typing import Any

from .itsm_remediation import (
    create_case,
    get_case,
    initialize_itsm_store,
    sync_case,
    verify_case,
)
from .decision_action_orchestration import transition

get_lifecycle = get_case

async def create_action_and_ticket(*, decision: dict[str, Any], owner: str, sla_hours: int, actor: str, provider: str, evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return await create_case(
        decision=decision,
        owner=owner,
        actor=actor,
        idempotency_key=f"legacy-{decision.get('decisionId', 'unknown')}-{provider}",
        providers=[provider],
        evidence=evidence or [],
        sla_hours=sla_hours,
        approved=False,
    )

async def transition_with_ticket(action_id: str, target_state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    return transition(action_id, target_state, actor, note)

async def validate_and_verify(action_id: str, actor: str, *, candidate: dict[str, Any], tools: list[str] | None = None, timeout: int = 180) -> dict[str, Any]:
    validation = dict(candidate)
    validation.setdefault("authorized", True)
    validation.setdefault("workspace", validation.get("workspace") or ".")
    return await verify_case(action_id, actor, validation, tools=tools)
