from __future__ import annotations

from typing import Any

from . import itsm_remediation as core
from .itsm_idempotency import create_or_reconcile
from . import itsm_sandbox
from .itsm_configuration import configuration_error

PROVIDERS = core.PROVIDERS
initialize_itsm_store = core.initialize_itsm_store
get_case = core.get_case
sync_case = core.sync_case
transition_case = core.transition_case
verify_case = core.verify_case


def get_case_by_idempotency(idempotency_key: str) -> dict[str, Any] | None:
    core.initialize_itsm_store()
    pool = core._db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT action_id FROM remediation_integration_records "
                "WHERE idempotency_key=%s ORDER BY record_id LIMIT 1",
                (idempotency_key,),
            )
            row = cur.fetchone()
        return core.get_case(row[0]) if row else None
    finally:
        pool.putconn(conn)


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
    """Canonical ITSM create path with sandbox support and retry-safe reconciliation."""
    core.initialize_itsm_store()
    evidence = evidence or []
    providers = list(dict.fromkeys(p.strip().lower() for p in (providers or list(PROVIDERS))))
    if not providers or any(p not in PROVIDERS for p in providers):
        raise ValueError("providers must contain only jira and/or servicenow")

    existing = get_case_by_idempotency(idempotency_key)
    if existing:
        return existing

    sandbox = itsm_sandbox.enabled()
    if not sandbox:
        invalid = {p: configuration_error(p) for p in providers}
        invalid = {p: error for p, error in invalid.items() if error}
        if invalid:
            raise RuntimeError(
                "ITSM configuration invalid; no external tickets were created: "
                + " | ".join(f"{p}: {error}" for p, error in invalid.items())
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
    if approved and action.get("state") == "pending":
        action = core.transition(action["actionId"], "approved", actor, "AADA approval recorded")

    request_hash = core._request_hash(action, normalized, evidence)
    for provider in providers:
        record = core._get_or_create_record(action["actionId"], provider, idempotency_key, request_hash)
        if record.get("request_hash") != request_hash:
            core._update_record(
                record["record_id"],
                integration_state="sync_error",
                last_error="Idempotency key already used with a different request payload",
            )
            raise ValueError("Idempotency key already used with a different request payload")
        if record.get("external_id"):
            continue

        if sandbox:
            result = itsm_sandbox.create(
                provider=provider,
                decision=normalized,
                action=action,
                evidence=evidence,
                idempotency_key=idempotency_key,
            )
            core._update_record(
                record["record_id"],
                integration_state="sandbox_created",
                external_state="created",
                external_id=result["external_id"],
                external_url=result["external_url"],
                response=result.get("response") or {},
                last_error=None,
            )
            core._audit(
                action["actionId"],
                "itsm.sandbox_created",
                actor,
                f"Created {provider} sandbox remediation ticket",
                {"provider": provider, "external_id": result["external_id"]},
            )
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
    if approved and case and case.get("all_required_created") and case["action"].get("state") == "approved":
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
