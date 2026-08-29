from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

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
    pool = _db(); conn = pool.getconn(); locked = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(914728311)")
            locked = True
            cur.execute("""CREATE TABLE IF NOT EXISTS remediation_integration_records (
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
            )""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_it_record_action ON remediation_integration_records(action_id, updated_at)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_it_record_state ON remediation_integration_records(integration_state, updated_at)")
            conn.commit(); _ready = True
    finally:
        if locked:
            try:
                with conn.cursor() as cur: cur.execute("SELECT pg_advisory_unlock(914728311)")
            except Exception: conn.rollback()
        pool.putconn(conn)


def _audit(action_id: str, event_type: str, actor: str, note: str, metadata: dict[str, Any] | None = None) -> None:
    """Persist lifecycle audit through the existing action event stream."""
    initialize_itsm_store(); pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO security_decision_action_events(action_id,event_type,actor,note,created_at) VALUES(%s,%s,%s,%s,%s)", (action_id, event_type, actor, note, _now()))
            conn.commit()
    finally:
        pool.putconn(conn)


def _configured(provider: str) -> bool:
    if provider == "jira":
        return all(os.getenv(k) for k in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"))
    return bool(os.getenv("SERVICENOW_BASE_URL") and (os.getenv("SERVICENOW_API_TOKEN") or (os.getenv("SERVICENOW_USERNAME") and os.getenv("SERVICENOW_PASSWORD"))))


def _request_hash(action: dict[str, Any], decision: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    payload = json.dumps({"action_id": action["actionId"], "decision": decision, "evidence": evidence}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def _ticket_payload(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]]) -> tuple[str, str, str]:
    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    confidence = float(decision.get("confidence", 0) or 0)
    severity = str(decision.get("severity") or ("critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 40 else "low")).lower()
    priority = {"critical": "1", "high": "2", "medium": "3", "low": "4"}.get(severity, "4")
    sla = 24 if score >= 85 else 72 if score >= 70 else 168 if score >= 40 else 720
    action_text = str(decision.get("recommended_action") or decision.get("recommendedAction") or action.get("recommendedAction") or "Investigate and remediate the finding.")
    description = "\n".join([
        "AegisScan remediation case",
        f"Action: {action['actionId']}",
        f"Decision: {decision.get('decisionId', action.get('decisionId'))}",
        f"Severity: {severity}",
        f"Dynamic risk: {score:.2f}",
        f"Fusion confidence: {confidence:.3f}",
        f"SLA target: {sla}h",
        f"Evidence count: {len(evidence)}",
        f"Recommended action: {action_text}",
    ])
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
        r = await client.post(f"{base}/rest/api/3/issue", json=payload); r.raise_for_status(); data = r.json()
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
    if token: headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers=headers, auth=auth) as client:
        r = await client.post(f"{base}/api/now/table/{table}", json=payload); r.raise_for_status(); wrapper = r.json()
    data = wrapper.get("result", wrapper); sys_id = data.get("sys_id")
    return {"status": "created", "provider": "servicenow", "external_id": sys_id, "external_url": f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}" if sys_id else None, "response": data}


async def _create_provider(provider: str, decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    if provider == "jira": return await _create_jira(decision, action, evidence, idem)
    if provider == "servicenow": return await _create_servicenow(decision, action, evidence, idem)
    raise ValueError(f"Unsupported provider: {provider}")


async def create_case(*, decision: dict[str, Any], owner: str, actor: str, idempotency_key: str, providers: list[str] | None = None, evidence: list[dict[str, Any]] | None = None, sla_hours: int | None = None, approved: bool = False) -> dict[str, Any]:
    initialize_itsm_store()
    providers = list(dict.fromkeys(p.strip().lower() for p in (providers or list(PROVIDERS))))
    if not providers or any(p not in PROVIDERS for p in providers): raise ValueError("providers must contain only jira and/or servicenow")
    action_decision = dict(decision)
    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    computed_sla = sla_hours or (24 if score >= 85 else 72 if score >= 70 else 168 if score >= 40 else 720)
    action_decision.setdefault("risk", int(round(score)))
    action_decision.setdefault("confidence", int(round(float(decision.get("confidence", 0)) * 100)))
    existing_action = _find_idempotent_action(idempotency_key)
    if existing_action:
        return get_case(existing_action["actionId"])
    action = create_action(action_decision, owner, computed_sla, actor)
    if approved:
        action = transition(action["actionId"], "approved", actor, "AADA approval recorded")
    evidence = evidence or []
    request_hash = _request_hash(action, decision, evidence)
    results = []
    for provider in providers:
        rec = _get_or_create_record(action["actionId"], provider, idempotency_key, request_hash)
        if rec["external_id"] or rec["integration_state"] == "created":
            results.append(_record_dict(rec)); continue
        if not _configured(provider):
            _update_record(rec["record_id"], integration_state="not_configured", last_error=f"{provider} credentials are not configured")
            results.append(_record_dict(_get_record(rec["record_id"]))); continue
        _update_record(rec["record_id"], integration_state="creating", attempt_count=rec["attempt_count"] + 1, last_error=None)
        try:
            result = await _create_provider(provider, decision, action, evidence, idempotency_key)
            _update_record(rec["record_id"], integration_state=result["status"], external_id=result.get("external_id"), external_url=result.get("external_url"), response=result.get("response") or {}, external_state="created", last_error=None)
            _audit(action["actionId"], "itsm.created", actor, f"Created {provider} remediation ticket", {"provider": provider, "external_id": result.get("external_id")})
        except Exception as exc:
            _update_record(rec["record_id"], integration_state="sync_error", last_error=f"{type(exc).__name__}: {exc}")
            _audit(action["actionId"], "itsm.create_failed", actor, f"Failed to create {provider} remediation ticket", {"provider": provider, "error": type(exc).__name__})
        results.append(_record_dict(_get_record(rec["record_id"])))
    return get_case(action["actionId"])


def _find_idempotent_action(idempotency_key: str) -> dict[str, Any] | None:
    initialize_itsm_store(); pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT action_id FROM remediation_integration_records WHERE idempotency_key=%s LIMIT 1", (idempotency_key,)); row = cur.fetchone()
            return get_action(row[0]) if row else None
    finally: pool.putconn(conn)


def _get_or_create_record(action_id: str, provider: str, idem: str, request_hash: str) -> dict[str, Any]:
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE action_id=%s AND provider=%s", (action_id, provider)); row = cur.fetchone()
            if row: return _row(row)
            now = _now()
            cur.execute("INSERT INTO remediation_integration_records(action_id,provider,idempotency_key,request_hash,integration_state,created_at,updated_at) VALUES(%s,%s,%s,%s,'sync_pending',%s,%s) RETURNING record_id", (action_id, provider, idem, request_hash, now, now))
            rid = cur.fetchone()[0]; conn.commit(); return _get_record(rid)
    finally: pool.putconn(conn)


def _get_record(record_id: int) -> dict[str, Any]:
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE record_id=%s", (record_id,)); return _row(cur.fetchone())
    finally: pool.putconn(conn)


def _row(row: tuple[Any, ...]) -> dict[str, Any]:
    keys = ("record_id","action_id","provider","idempotency_key","request_hash","external_id","external_url","integration_state","external_state","response","last_error","attempt_count","validation","created_at","updated_at")
    return dict(zip(keys, row))


def _record_dict(rec: dict[str, Any]) -> dict[str, Any]:
    return {**rec, "created_at": rec["created_at"].isoformat(), "updated_at": rec["updated_at"].isoformat()}


def _update_record(record_id: int, **fields: Any) -> None:
    allowed = {"integration_state","external_state","external_id","external_url","response","last_error","attempt_count","validation"}
    updates = [(k, v) for k, v in fields.items() if k in allowed]
    if not updates: return
    values = [json.dumps(v) if isinstance(v, (dict, list)) else v for _, v in updates] + [_now(), record_id]
    assignments = [sql.SQL("{}=%s").format(sql.Identifier(k)) for k, _ in updates]
    statement = sql.SQL("UPDATE remediation_integration_records SET {} , updated_at=%s WHERE record_id=%s").format(sql.SQL(", ").join(assignments))
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(statement, values); conn.commit()
    finally: pool.putconn(conn)


async def sync_case(action_id: str, actor: str, providers: list[str] | None = None) -> dict[str, Any]:
    case = get_case(action_id)
    if not case: raise KeyError(action_id)
    requested = providers or list(PROVIDERS)
    results = []
    for rec in case["integrations"]:
        if rec["provider"] not in requested or rec.get("external_id") or not _configured(rec["provider"]):
            results.append(rec); continue
        try:
            decision = case["decision"]
            result = await _create_provider(rec["provider"], decision, case["action"], case.get("evidence", []), rec["idempotency_key"])
            _update_record(rec["record_id"], integration_state=result["status"], external_id=result.get("external_id"), external_url=result.get("external_url"), response=result.get("response") or {}, external_state="created", last_error=None, attempt_count=rec["attempt_count"] + 1)
            results.append(_record_dict(_get_record(rec["record_id"])))
            _audit(action_id, "itsm.synced", actor, f"Synchronized {rec['provider']} remediation ticket", {"provider": rec["provider"], "external_id": result.get("external_id")})
        except Exception as exc:
            _update_record(rec["record_id"], integration_state="sync_error", last_error=f"{type(exc).__name__}: {exc}", attempt_count=rec["attempt_count"] + 1)
            results.append(_record_dict(_get_record(rec["record_id"])))
    return get_case(action_id)
