from __future__ import annotations

import os
from typing import Any

from . import itsm_remediation_v2 as core
from .itsm_configuration import configuration_error
from .itsm_idempotency import create_or_reconcile

PROVIDERS = core.PROVIDERS
initialize_itsm_store = core.initialize_itsm_store
get_case = core.get_case
get_case_by_idempotency = core.get_case_by_idempotency
sync_case = core.sync_case
transition_case = core.transition_case
verify_case = core.verify_case
get_lifecycle = core.get_lifecycle
transition_with_ticket = core.transition_with_ticket
validate_and_verify = core.validate_and_verify


async def create_case(
    *,
    decision: dict[str, Any],
    owner: str,
    actor: str,
    idempotency_key: str,
    providers: list[str] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    sla_hours: int | None = None,
    approved: bool = False,
) -> dict[str, Any]:
    """Canonical ITSM create path with DB and provider-side idempotency."""
    initialize_itsm_store()
    evidence = evidence or []
    providers = list(dict.fromkeys(p.strip().lower() for p in (providers or list(PROVIDERS))))
    if not providers or any(p not in PROVIDERS for p in providers):
        raise ValueError("providers must contain only jira and/or servicenow")

    if not os.getenv("SERVICENOW_IDEMPOTENCY_FIELD"):
        os.environ["SERVICENOW_IDEMPOTENCY_FIELD"] = "correlation_id"

    existing = await get_case_by_idempotency(idempotency_key)
    if existing:
        return existing

    invalid = {provider: configuration_error(provider) for provider in providers}
    invalid = {provider: error for provider, error in invalid.items() if error}
    if invalid:
        raise RuntimeError(
            "ITSM configuration invalid; no external tickets were created: "
            + " | ".join(f"{provider}: {error}" for provider, error in invalid.items())
        )

    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    computed_sla = sla_hours or (24 if score >= 85 else 72 if score >= 70 else 168 if score >= 40 else 720)
    normalized = dict(decision)
    normalized.setdefault("risk", int(round(score)))
    normalized.setdefault("confidence", int(round(float(decision.get("confidence", 0) or 0) * 100)))
    action = core.create_action(
        normalized,
        owner,
        computed_sla,
        actor,
        idempotency_key=idempotency_key,
    )
    if approved:
        action = core.transition(action["actionId"], "approved", actor, "AADA approval recorded")

    request_hash = core._request_hash(normalized, evidence)
    for provider in providers:
        record = core._get_or_create_record(action["actionId"], provider, idempotency_key, request_hash)
        if record.get("request_hash") != request_hash:
            core._update_record(record["record_id"], integration_state="sync_error", last_error="Idempotency key reused with a different request payload")
            raise ValueError("Idempotency key already used with a different request payload")
        if record.get("external_id"):
            continue
        _update_error = configuration_error(provider)
        if _update_error:
            core._update_record(record["record_id"], integration_state="not_configured", last_error=_update_error)
            core._audit(action["actionId"], "itsm.provider_not_configured", actor, f"{provider} configuration rejected", {"reason": _update_error})
            continue
        try:
            result = await create_or_reconcile(
                provider=provider,
                decision=normalized,
                action=action,
                evidence=evidence,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:
            core._update_record(
                record["record_id"],
                integration_state="sync_error",
                last_error=f"{type(exc).__name__}: {exc}",
            )
            core._audit(
                action["actionId"],
                "itsm.create_failed",
                actor,
                f"{provider} create/reconcile failed",
                {"provider": provider, "error": type(exc).__name__},
            )
            continue
        if result.get("external_id"):
            core._update_record(
                record["record_id"],
                integration_state="created" if result.get("status") == "created" else "synced",
                external_state="created",
                external_id=result["external_id"],
                external_url=result.get("external_url"),
                response=result.get("response") or {},
                last_error=None,
            )

    case = core.get_case(action["actionId"])
    if approved and case and case["all_required_created"]:
        core.transition(action["actionId"], "assigned", actor, "All required ITSM records created")
        core.transition(action["actionId"], "in_progress", actor, "Remediation work opened across all required ITSM records")
        await core._sync_external_states(action["actionId"], "in_progress", actor, "Remediation work opened")
    return core.get_case(action["actionId"])


async def create_action_and_ticket(
    *,
    decision: dict[str, Any],
    owner: str,
    sla_hours: int,
    actor: str,
    provider: str,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
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
