from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
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
    set_sql = ", ".join(f"{k}=%s" for k, _ in updates) + ", updated_at=%s"
    values = [json.dumps(v) if isinstance(v, (dict, list)) else v for _, v in updates] + [_now(), record_id]
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE remediation_integration_records SET {set_sql} WHERE record_id=%s", values); conn.commit()
    finally: pool.putconn(conn)


async def sync_case(action_id: str, actor: str, providers: list[str] | None = None) -> dict[str, Any]:
    case = get_case(action_id)
    if not case: raise KeyError(action_id)
    requested = providers or list(PROVIDERS)
    results = []
    for rec in case["integrations"]:
        if rec["provider"] not in requested or rec.get("external_id") or not _configured(rec["provider"]):
            results.append(rec); continue
        decision = {"decisionId": case["action"]["decisionId"], "label": case["action"]["title"], "final_score": case["action"]["riskBefore"], "confidence": case["action"]["confidenceBefore"] / 100, "severity": "critical" if case["action"]["riskBefore"] >= 85 else "high" if case["action"]["riskBefore"] >= 70 else "medium"}
        _update_record(rec["record_id"], integration_state="creating", attempt_count=rec["attempt_count"] + 1, last_error=None)
        try:
            result = await _create_provider(rec["provider"], decision, case["action"], [], rec["idempotency_key"])
            _update_record(rec["record_id"], integration_state=result["status"], external_id=result.get("external_id"), external_url=result.get("external_url"), response=result.get("response") or {}, external_state="created", last_error=None)
            _audit(action_id, "itsm.sync", actor, f"Retried {rec['provider']} ticket synchronization", {"provider": rec["provider"]})
        except Exception as exc:
            _update_record(rec["record_id"], integration_state="sync_error", last_error=f"{type(exc).__name__}: {exc}")
        results.append(_record_dict(_get_record(rec["record_id"])))
    return get_case(action_id)


def get_case(action_id: str) -> dict[str, Any] | None:
    action = get_action(action_id)
    if action is None: return None
    initialize_itsm_store(); pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE action_id=%s ORDER BY provider", (action_id,))
            integrations = [_record_dict(_row(row)) for row in cur.fetchall()]
    finally: pool.putconn(conn)
    return {"action": action, "integrations": integrations, "required_providers": list(PROVIDERS), "all_required_created": bool(integrations) and all(i.get("external_id") for i in integrations if i["provider"] in PROVIDERS), "idempotency_keys": sorted({i["idempotency_key"] for i in integrations})}


async def transition_case(action_id: str, target_state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    case = get_case(action_id)
    if not case: raise KeyError(action_id)
    updated = transition(action_id, target_state, actor, note)
    await _sync_external_states(action_id, target_state, actor, note)
    return get_case(action_id)


async def verify_case(action_id: str, actor: str, candidate: dict[str, Any], tools: list[str] | None = None, timeout: int = 180) -> dict[str, Any]:
    case = get_case(action_id)
    if not case: raise KeyError(action_id)
    action = case["action"]
    if action["state"] == "in_progress":
        transition(action_id, "awaiting_revalidation", actor, "Automatic remediation revalidation started")
    elif action["state"] != "awaiting_revalidation":
        raise ValueError(f"Action must be in_progress or awaiting_revalidation, got {action['state']}")
    result = await RemediationValidationSuite().validate_workspace(candidate, tools=tools, timeout=timeout)
    before = float(candidate.get("risk_before", action.get("riskBefore", 0)))
    after = float(candidate.get("risk_after", before))
    result["risk_diff"] = RemediationValidationSuite.compare_scores(before, after)
    passed = bool(result.get("passed")) and not result["risk_diff"].get("regressed")
    target = "verified" if passed else "in_progress"
    if passed:
        updated = transition(action_id, "verified", actor, "Real validation passed; remediation verified")
    else:
        updated = transition(action_id, "in_progress", actor, "Validation failed or risk regressed; remediation reopened")
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE remediation_integration_records SET validation=%s, integration_state=CASE WHEN %s='verified' THEN integration_state ELSE 'sync_pending' END, updated_at=%s WHERE action_id=%s", (json.dumps(result), target, _now(), action_id)); conn.commit()
    finally: pool.putconn(conn)
    await _sync_external_states(action_id, target, actor, json.dumps(result.get("summary", {})))
    _audit(action_id, "itsm.verified" if passed else "itsm.reopened", actor, "Remediation lifecycle verification decision recorded", {"passed": passed, "validation": result})
    return {"action": updated, "validation": result, "case": get_case(action_id)}


async def _sync_external_states(action_id: str, state: str, actor: str, note: str | None) -> None:
    case = get_case(action_id)
    if not case: return
    for rec in case["integrations"]:
        if not rec.get("external_id"): continue
        try:
            if rec["provider"] == "jira":
                await _jira_transition(rec["external_id"], state)
            else:
                await _servicenow_transition(rec["external_id"], state, note)
            _update_record(rec["record_id"], integration_state="synced", external_state=state, last_error=None)
            _audit(action_id, "itsm.state_synced", actor, f"Synchronized {rec['provider']} ticket to {state}", {"provider": rec["provider"], "external_id": rec["external_id"]})
        except Exception as exc:
            _update_record(rec["record_id"], integration_state="sync_error", last_error=f"{type(exc).__name__}: {exc}")
            _audit(action_id, "itsm.state_sync_failed", actor, f"Failed to synchronize {rec['provider']} ticket", {"provider": rec["provider"], "error": type(exc).__name__})


async def _jira_transition(issue_key: str, state: str) -> None:
    base = os.getenv("JIRA_BASE_URL", "").rstrip("/"); token, email = os.getenv("JIRA_API_TOKEN"), os.getenv("JIRA_USER_EMAIL")
    if not all((base, token, email)): raise RuntimeError("Jira credentials are not configured")
    wanted_map = {"pending": os.getenv("JIRA_STATUS_PENDING", "To Do"), "approved": os.getenv("JIRA_STATUS_APPROVED", "In Progress"), "assigned": os.getenv("JIRA_STATUS_ASSIGNED", "In Progress"), "in_progress": os.getenv("JIRA_STATUS_IN_PROGRESS", "In Progress"), "awaiting_revalidation": os.getenv("JIRA_STATUS_REVALIDATION", "In Review"), "verified": os.getenv("JIRA_STATUS_VERIFIED", "Done"), "rejected": os.getenv("JIRA_STATUS_REJECTED", "Won't Do"), "deferred": os.getenv("JIRA_STATUS_DEFERRED", "To Do")}
    target = wanted_map.get(state, "In Progress")
    async with httpx.AsyncClient(timeout=20, auth=(email, token), headers={"Accept":"application/json","Content-Type":"application/json"}) as client:
        r = await client.get(f"{base}/rest/api/3/issue/{issue_key}/transitions"); r.raise_for_status(); data = r.json()
        match = next((str(x.get("id")) for x in data.get("transitions", []) if str(x.get("to",{}).get("name","")).lower() == target.lower()), None)
        if not match: raise RuntimeError(f"No Jira transition available to '{target}'")
        p = await client.post(f"{base}/rest/api/3/issue/{issue_key}/transitions", json={"transition":{"id":match}}); p.raise_for_status()


async def _servicenow_transition(sys_id: str, state: str, note: str | None) -> None:
    base = os.getenv("SERVICENOW_BASE_URL", "").rstrip("/"); table = os.getenv("SERVICENOW_TABLE", "incident")
    headers = {"Accept":"application/json","Content-Type":"application/json"}
    token = os.getenv("SERVICENOW_API_TOKEN"); username, password = os.getenv("SERVICENOW_USERNAME"), os.getenv("SERVICENOW_PASSWORD")
    auth = None if token else (username, password)
    if token: headers["Authorization"] = f"Bearer {token}"
    state_map = {"pending": os.getenv("SERVICENOW_STATE_PENDING", "1"), "approved": os.getenv("SERVICENOW_STATE_APPROVED", "2"), "assigned": os.getenv("SERVICENOW_STATE_ASSIGNED", "2"), "in_progress": os.getenv("SERVICENOW_STATE_IN_PROGRESS", "2"), "awaiting_revalidation": os.getenv("SERVICENOW_STATE_REVALIDATION", "2"), "verified": os.getenv("SERVICENOW_STATE_VERIFIED", "7"), "rejected": os.getenv("SERVICENOW_STATE_REJECTED", "8"), "deferred": os.getenv("SERVICENOW_STATE_DEFERRED", "3")}
    if not base or not (token or (username and password)): raise RuntimeError("ServiceNow credentials are not configured")
    payload = {"state": state_map.get(state, "2"), "comments": note or f"AegisScan lifecycle state: {state}"}
    async with httpx.AsyncClient(timeout=20, headers=headers, auth=auth) as client:
        r = await client.patch(f"{base}/api/now/table/{table}/{sys_id}", json=payload); r.raise_for_status()
