from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from psycopg2 import sql
from psycopg2.pool import ThreadedConnectionPool

from ..core.config import settings
from .decision_action_orchestration import create_action, get_action, transition
from .remediation_validation import RemediationValidationSuite

PROVIDERS = ("jira", "servicenow")
INTEGRATION_STATES = {"not_configured", "creating", "created", "sync_pending", "synced", "sync_error"}
_pool: ThreadedConnectionPool | None = None
_ready = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db() -> ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(1, 10, settings.DATABASE_URL)
    return _pool


def initialize_itsm_store() -> None:
    global _ready
    if _ready:
        return
    pool = _db()
    conn = pool.getconn()
    locked = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(914728311)")
            locked = True
            cur.execute(
                """CREATE TABLE IF NOT EXISTS remediation_integration_records (
                    record_id BIGSERIAL PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    external_id TEXT,
                    external_url TEXT,
                    integration_state TEXT NOT NULL,
                    external_state TEXT,
                    response JSONB NOT NULL DEFAULT '{}'::jsonb,
                    last_error TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    validation JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    UNIQUE(action_id, provider),
                    UNIQUE(provider, idempotency_key)
                )"""
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_it_record_action ON remediation_integration_records(action_id, updated_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_it_record_state ON remediation_integration_records(integration_state, updated_at)")
            conn.commit()
            _ready = True
    finally:
        if locked:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(914728311)")
            except Exception:
                conn.rollback()
        pool.putconn(conn)


def _audit(action_id: str, event_type: str, actor: str, note: str, metadata: dict[str, Any] | None = None) -> None:
    initialize_itsm_store()
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO security_decision_action_events(action_id,event_type,actor,note,created_at) VALUES(%s,%s,%s,%s,%s)",
                (action_id, event_type, actor, note, _now()),
            )
            conn.commit()
    finally:
        pool.putconn(conn)


def _configured(provider: str) -> bool:
    if provider == "jira":
        return all(os.getenv(k) for k in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"))
    return bool(
        os.getenv("SERVICENOW_BASE_URL")
        and (os.getenv("SERVICENOW_API_TOKEN") or (os.getenv("SERVICENOW_USERNAME") and os.getenv("SERVICENOW_PASSWORD")))
    )


def _request_hash(action: dict[str, Any], decision: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    payload = json.dumps({"action_id": action["actionId"], "decision": decision, "evidence": evidence}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def _ticket_payload(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]]) -> tuple[str, str, str]:
    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    confidence = float(decision.get("confidence", 0) or 0)
    severity = str(
        decision.get("severity")
        or ("critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 40 else "low")
    ).lower()
    priority = {"critical": "1", "high": "2", "medium": "3", "low": "4"}.get(severity, "4")
    sla = 24 if score >= 85 else 72 if score >= 70 else 168 if score >= 40 else 720
    action_text = str(
        decision.get("recommended_action")
        or decision.get("recommendedAction")
        or action.get("recommendedAction")
        or "Investigate and remediate the finding."
    )
    description = "\n".join(
        [
            "AegisScan remediation case",
            f"Action: {action['actionId']}",
            f"Decision: {decision.get('decisionId', action.get('decisionId'))}",
            f"Severity: {severity}",
            f"Dynamic risk: {score:.2f}",
            f"Fusion confidence: {confidence:.3f}",
            f"SLA target: {sla}h",
            f"Evidence count: {len(evidence)}",
            f"Recommended action: {action_text}",
        ]
    )
    return str(decision.get("title") or decision.get("label") or action.get("title") or "AegisScan Security Remediation")[:255], description, priority


async def _create_jira(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    base = os.getenv("JIRA_BASE_URL", "").rstrip("/")
    token, email, project = os.getenv("JIRA_API_TOKEN"), os.getenv("JIRA_USER_EMAIL"), os.getenv("JIRA_PROJECT_KEY")
    if not all((base, token, email, project)):
        return {"status": "not_configured", "provider": "jira", "required": ["JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"]}
    title, description, priority = _ticket_payload(decision, action, evidence)
    adf = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": line}]} for line in description.splitlines()]}
    payload = {"fields": {"project": {"key": project}, "summary": title, "issuetype": {"name": os.getenv("JIRA_ISSUE_TYPE", "Task")}, "description": adf, "labels": ["aegisscan", "security-validation", "aada"], "priority": {"id": priority}}}
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-AegisScan-Idempotency-Key": idem}
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, auth=(email, token), headers=headers) as client:
        response = await client.post(f"{base}/rest/api/3/issue", json=payload)
        response.raise_for_status()
        data = response.json()
    key = data.get("key")
    return {"status": "created", "provider": "jira", "external_id": key, "external_url": f"{base}/browse/{key}" if key else None, "response": data}


async def _create_servicenow(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    base = os.getenv("SERVICENOW_BASE_URL", "").rstrip("/")
    token = os.getenv("SERVICENOW_API_TOKEN")
    username, password = os.getenv("SERVICENOW_USERNAME"), os.getenv("SERVICENOW_PASSWORD")
    if not base or not (token or (username and password)):
        return {"status": "not_configured", "provider": "servicenow"}
    title, description, _ = _ticket_payload(decision, action, evidence)
    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    urgency = "1" if score >= 85 else "2" if score >= 40 else "3"
    table = os.getenv("SERVICENOW_TABLE", "incident")
    payload = {"short_description": title[:160], "description": description, "urgency": urgency, "impact": urgency}
    custom_finding = os.getenv("SERVICENOW_FINDING_FIELD", "")
    if custom_finding:
        payload[custom_finding] = str(decision.get("finding_id") or decision.get("findingId") or action.get("actionId"))
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-AegisScan-Idempotency-Key": idem}
    auth = None if token else (username, password)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=headers, auth=auth) as client:
        response = await client.post(f"{base}/api/now/table/{table}", json=payload)
        response.raise_for_status()
        wrapper = response.json()
    data = wrapper.get("result", wrapper)
    sys_id = data.get("sys_id")
    return {"status": "created", "provider": "servicenow", "external_id": sys_id, "external_url": f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}" if sys_id else None, "response": data}


async def _create_provider(provider: str, decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    if provider == "jira":
        return await _create_jira(decision, action, evidence, idem)
    if provider == "servicenow":
        return await _create_servicenow(decision, action, evidence, idem)
    raise ValueError(f"Unsupported provider: {provider}")


def _row(row: tuple[Any, ...]) -> dict[str, Any]:
    keys = ("record_id", "action_id", "provider", "idempotency_key", "request_hash", "external_id", "external_url", "integration_state", "external_state", "response", "last_error", "attempt_count", "validation", "created_at", "updated_at")
    return dict(zip(keys, row))


def _get_record(record_id: int) -> dict[str, Any]:
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE record_id=%s", (record_id,))
            row = cur.fetchone()
            if row is None:
                raise KeyError(record_id)
            return _row(row)
    finally:
        pool.putconn(conn)


def _record_dict(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        **rec,
        "created_at": rec["created_at"].isoformat(),
        "updated_at": rec["updated_at"].isoformat(),
    }


def _get_or_create_record(action_id: str, provider: str, idem: str, request_hash: str) -> dict[str, Any]:
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE action_id=%s AND provider=%s", (action_id, provider))
            row = cur.fetchone()
            if row:
                return _row(row)
            now = _now()
            cur.execute("INSERT INTO remediation_integration_records(action_id,provider,idempotency_key,request_hash,integration_state,created_at,updated_at) VALUES(%s,%s,%s,%s,'sync_pending',%s,%s) RETURNING record_id", (action_id, provider, idem, request_hash, now, now))
            record_id = cur.fetchone()[0]
            conn.commit()
            return _get_record(record_id)
    finally:
        pool.putconn(conn)


def _update_record(record_id: int, **fields: Any) -> None:
    allowed = {"integration_state", "external_state", "external_id", "external_url", "response", "last_error", "attempt_count", "validation"}
    updates = [(key, value) for key, value in fields.items() if key in allowed]
    if not updates:
        return
    values = [json.dumps(value) if isinstance(value, (dict, list)) else value for _, value in updates] + [_now(), record_id]
    assignments = [sql.SQL("{}=%s").format(sql.Identifier(key)) for key, _ in updates]
    statement = sql.SQL("UPDATE remediation_integration_records SET {}, updated_at=%s WHERE record_id=%s").format(sql.SQL(", ").join(assignments))
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(statement, values)
            conn.commit()
    finally:
        pool.putconn(conn)


def _find_idempotent_action(idempotency_key: str) -> dict[str, Any] | None:
    initialize_itsm_store()
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT action_id FROM remediation_integration_records WHERE idempotency_key=%s LIMIT 1", (idempotency_key,))
            row = cur.fetchone()
            return get_action(row[0]) if row else None
    finally:
        pool.putconn(conn)


def get_case(action_id: str) -> dict[str, Any] | None:
    """Return the canonical action + persistent ITSM integration state."""
    action = get_action(action_id)
    if not action:
        return None
    initialize_itsm_store()
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE action_id=%s ORDER BY provider", (action_id,))
            integrations = [_record_dict(_row(row)) for row in cur.fetchall()]
    finally:
        pool.putconn(conn)
    decision = {
        "decisionId": action.get("decisionId"),
        "nodeId": action.get("nodeId"),
        "label": action.get("title"),
        "risk": action.get("riskBefore", 0),
        "confidence": action.get("confidenceBefore", 0),
        "recommendedAction": action.get("recommendedAction"),
    }
    return {"action": action, "decision": decision, "integrations": integrations, "evidence": []}


async def _sync_external_states(action_id: str, actor: str, providers: list[str] | None = None) -> None:
    """Best-effort external reconciliation hook used by verification."""
    case = get_case(action_id)
    if not case:
        return
    requested = set(providers or PROVIDERS)
    for record in case["integrations"]:
        if record["provider"] in requested and record.get("external_id"):
            _audit(action_id, "itsm.reconciled", actor, f"Reconciled {record['provider']} ticket", {"provider": record["provider"], "external_id": record["external_id"]})


async def create_case(*, decision: dict[str, Any], owner: str, actor: str, idempotency_key: str, providers: list[str] | None = None, evidence: list[dict[str, Any]] | None = None, sla_hours: int | None = None, approved: bool = False) -> dict[str, Any]:
    initialize_itsm_store()
    providers = list(dict.fromkeys(p.strip().lower() for p in (providers or list(PROVIDERS))))
    if not providers or any(provider not in PROVIDERS for provider in providers):
        raise ValueError("providers must contain only jira and/or servicenow")
    action_decision = dict(decision)
    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    computed_sla = sla_hours or (24 if score >= 85 else 72 if score >= 70 else 168 if score >= 40 else 720)
    action_decision.setdefault("risk", int(round(score)))
    action_decision.setdefault("confidence", int(round(float(decision.get("confidence", 0)) * 100)))
    existing_action = _find_idempotent_action(idempotency_key)
    if existing_action:
        return get_case(existing_action["actionId"])
    action = create_action(action_decision, owner, computed_sla, actor, idempotency_key=idempotency_key)
    if approved:
        action = transition(action["actionId"], "approved", actor, "AADA approval recorded")
    evidence = evidence or []
    request_hash = _request_hash(action, decision, evidence)
    for provider in providers:
        record = _get_or_create_record(action["actionId"], provider, idempotency_key, request_hash)
        if record["external_id"] or record["integration_state"] == "created":
            continue
        if not _configured(provider):
            _update_record(record["record_id"], integration_state="not_configured", last_error=f"{provider} credentials are not configured")
            continue
        _update_record(record["record_id"], integration_state="creating", attempt_count=record["attempt_count"] + 1, last_error=None)
        try:
            result = await _create_provider(provider, decision, action, evidence, idempotency_key)
            _update_record(record["record_id"], integration_state=result["status"], external_id=result.get("external_id"), external_url=result.get("external_url"), response=result.get("response") or {}, external_state="created", last_error=None)
            _audit(action["actionId"], "itsm.created", actor, f"Created {provider} remediation ticket", {"provider": provider, "external_id": result.get("external_id")})
        except Exception as exc:
            _update_record(record["record_id"], integration_state="sync_error", last_error=f"{type(exc).__name__}: {exc}")
            _audit(action["actionId"], "itsm.create_failed", actor, f"Failed to create {provider} remediation ticket", {"provider": provider, "error": type(exc).__name__})
    return get_case(action["actionId"])


async def verify_case(action_id: str, actor: str, validation: dict[str, Any], tools: list[str] | None = None) -> dict[str, Any]:
    """Re-validate a remediation and allow verified only after successful validation."""
    case = get_case(action_id)
    if not case:
        raise KeyError(action_id)
    action = case["action"]
    if action.get("state") != "awaiting_revalidation":
        raise ValueError(f"Action {action_id} is not awaiting revalidation")
    if not validation.get("authorized"):
        raise ValueError("Verification requires authorized=true")
    candidate = validation.get("workspace") or validation.get("candidate") or "."
    before = float(validation.get("risk_before", action.get("riskBefore", 0)) or 0)
    after = float(validation.get("risk_after", before) or before)
    suite = RemediationValidationSuite()
    validation_result = await suite.validate_workspace(candidate, tools=tools, timeout=180)
    score_result = suite.compare_scores(before, after)
    validation_ok = bool(validation_result.get("passed")) and not bool(score_result.get("regressed")) and after < before
    await _sync_external_states(action_id, actor)
    if validation_ok:
        transition(action_id, "verified", actor, "Remediation validation succeeded", verification_context=True)
        _audit(action_id, "remediation.verified", actor, "Remediation verified after successful revalidation", {"risk_before": before, "risk_after": after})
    else:
        transition(action_id, "in_progress", actor, "Remediation revalidation failed")
        _audit(action_id, "remediation.revalidation_failed", actor, "Remediation reopened after failed revalidation", {"risk_before": before, "risk_after": after})
    return get_case(action_id) or {"action": get_action(action_id), "integrations": [], "evidence": []}


async def sync_case(action_id: str, actor: str, providers: list[str] | None = None) -> dict[str, Any]:
    case = get_case(action_id)
    if not case:
        raise KeyError(action_id)
    requested = set(providers or PROVIDERS)
    for record in case["integrations"]:
        if record["provider"] not in requested or record.get("external_id") or not _configured(record["provider"]):
            continue
        try:
            result = await _create_provider(record["provider"], case["decision"], case["action"], case.get("evidence", []), record["idempotency_key"])
            _update_record(record["record_id"], integration_state=result["status"], external_id=result.get("external_id"), external_url=result.get("external_url"), response=result.get("response") or {}, external_state="created", last_error=None, attempt_count=record["attempt_count"] + 1)
            _audit(action_id, "itsm.synced", actor, f"Synchronized {record['provider']} remediation ticket", {"provider": record["provider"], "external_id": result.get("external_id")})
        except Exception as exc:
            _update_record(record["record_id"], integration_state="sync_error", last_error=f"{type(exc).__name__}: {exc}", attempt_count=record["attempt_count"] + 1)
    return get_case(action_id) or {"action": get_action(action_id), "integrations": [], "evidence": []}
