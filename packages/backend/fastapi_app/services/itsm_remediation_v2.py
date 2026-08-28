from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

import httpx
from psycopg2.pool import ThreadedConnectionPool

from ..core.config import settings
from .decision_action_orchestration import create_action, get_action, transition
from .remediation_validation import RemediationValidationSuite

PROVIDERS = ("jira", "servicenow")
_POOL: ThreadedConnectionPool | None = None
_READY = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db() -> ThreadedConnectionPool:
    global _POOL
    if _POOL is None:
        _POOL = ThreadedConnectionPool(1, 10, settings.DATABASE_URL)
    return _POOL


def initialize_itsm_store() -> None:
    global _READY
    if _READY:
        return
    pool = _db(); conn = pool.getconn(); locked = False
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(914728311)"); locked = True
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
            conn.commit(); _READY = True
    finally:
        if locked:
            try:
                with conn.cursor() as cur: cur.execute("SELECT pg_advisory_unlock(914728311)")
            except Exception: conn.rollback()
        pool.putconn(conn)


def _audit(action_id: str, event_type: str, actor: str, note: str, metadata: dict[str, Any] | None = None) -> None:
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            full_note = note if not metadata else f"{note} | {json.dumps(metadata, sort_keys=True, default=str)}"
            cur.execute("INSERT INTO security_decision_action_events(action_id,event_type,actor,note,created_at) VALUES(%s,%s,%s,%s,%s)", (action_id, event_type, actor, full_note, _now()))
            conn.commit()
    finally: pool.putconn(conn)


def _configured(provider: str) -> bool:
    if provider == "jira":
        return all(os.getenv(k) for k in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"))
    return bool(os.getenv("SERVICENOW_BASE_URL") and (os.getenv("SERVICENOW_API_TOKEN") or (os.getenv("SERVICENOW_USERNAME") and os.getenv("SERVICENOW_PASSWORD"))))


def _request_hash(decision: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    body = json.dumps({"decision": decision, "evidence": evidence}, sort_keys=True, default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def _severity_and_sla(decision: dict[str, Any]) -> tuple[str, int]:
    score = float(decision.get("final_score", decision.get("risk", 0)) or 0)
    severity = str(decision.get("severity") or ("critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 40 else "low")).lower()
    return severity, (24 if score >= 85 else 72 if score >= 70 else 168 if score >= 40 else 720)


def _description(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], sla: int, severity: str) -> str:
    return "\n".join([
        "AegisScan remediation case",
        f"Action: {action['actionId']}",
        f"Decision: {decision.get('decisionId', action.get('decisionId'))}",
        f"Severity: {severity}",
        f"Dynamic risk: {float(decision.get('final_score', decision.get('risk', 0)) or 0):.2f}",
        f"Fusion confidence: {float(decision.get('confidence', 0) or 0):.3f}",
        f"SLA target: {sla}h",
        f"Evidence count: {len(evidence)}",
        f"Recommended action: {decision.get('recommended_action') or decision.get('recommendedAction') or action.get('recommendedAction') or 'Investigate and remediate the finding.'}",
    ])


def _row(row: tuple[Any, ...]) -> dict[str, Any]:
    keys = ("record_id","action_id","provider","idempotency_key","request_hash","external_id","external_url","integration_state","external_state","response","last_error","attempt_count","validation","created_at","updated_at")
    return dict(zip(keys, row))


def _record_dict(rec: dict[str, Any]) -> dict[str, Any]:
    return {**rec, "created_at": rec["created_at"].isoformat(), "updated_at": rec["updated_at"].isoformat()}


def _get_record(record_id: int) -> dict[str, Any]:
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE record_id=%s", (record_id,))
            row = cur.fetchone()
            if row is None: raise KeyError(record_id)
            return _row(row)
    finally: pool.putconn(conn)


def _get_or_create_record(action_id: str, provider: str, idem: str, request_hash: str) -> dict[str, Any]:
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE action_id=%s AND provider=%s", (action_id, provider))
            row = cur.fetchone()
            if row: return _row(row)
            now = _now()
            cur.execute("INSERT INTO remediation_integration_records(action_id,provider,idempotency_key,request_hash,integration_state,created_at,updated_at) VALUES(%s,%s,%s,%s,'sync_pending',%s,%s) ON CONFLICT(action_id,provider) DO UPDATE SET updated_at=EXCLUDED.updated_at RETURNING record_id", (action_id, provider, idem, request_hash, now, now))
            record_id = cur.fetchone()[0]; conn.commit(); return _get_record(record_id)
    finally: pool.putconn(conn)


def _update_record(record_id: int, **fields: Any) -> None:
    allowed = {"integration_state","external_state","external_id","external_url","response","last_error","attempt_count","validation"}
    updates = [(k, v) for k, v in fields.items() if k in allowed]
    if not updates: return
    sql = ", ".join(f"{k}=%s" for k, _ in updates) + ", updated_at=%s"
    values = [json.dumps(v) if isinstance(v, (dict, list)) else v for _, v in updates] + [_now(), record_id]
    pool = _db(); conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE remediation_integration_records SET {sql} WHERE record_id=%s", values); conn.commit()
    finally: pool.putconn(conn)


async def _create_jira(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    base, token, email, project = (os.getenv("JIRA_BASE_URL", "").rstrip("/"), os.getenv("JIRA_API_TOKEN"), os.getenv("JIRA_USER_EMAIL"), os.getenv("JIRA_PROJECT_KEY"))
    if not all((base, token, email, project)): return {"status":"not_configured","provider":"jira"}
    severity, sla = _severity_and_sla(decision); description = _description(decision, action, evidence, sla, severity)
    adf = {"type":"doc","version":1,"content":[{"type":"paragraph","content":[{"type":"text","text":line}]} for line in description.splitlines()]}
    idem_label = "aegis-idem-" + idem[:16]
    payload = {"fields":{"project":{"key":project},"summary":str(decision.get("title") or decision.get("label") or action.get("title") or "AegisScan Security Remediation")[:255],"issuetype":{"name":os.getenv("JIRA_ISSUE_TYPE","Task")},"description":adf,"labels":["aegisscan","security-validation","aada",idem_label],"priority":{"id":{"critical":"1","high":"2","medium":"3","low":"4"}.get(severity,"4")}}}
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, auth=(email, token), headers={"Accept":"application/json","Content-Type":"application/json","X-AegisScan-Idempotency-Key":idem}) as client:
        response = await client.post(f"{base}/rest/api/3/issue", json=payload); response.raise_for_status(); data=response.json()
    key=data.get("key")
    return {"status":"created","provider":"jira","external_id":key,"external_url":f"{base}/browse/{key}" if key else None,"response":data}


async def _create_servicenow(decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    base=os.getenv("SERVICENOW_BASE_URL","").rstrip("/"); token=os.getenv("SERVICENOW_API_TOKEN"); username=os.getenv("SERVICENOW_USERNAME"); password=os.getenv("SERVICENOW_PASSWORD")
    if not base or not (token or (username and password)): return {"status":"not_configured","provider":"servicenow"}
    severity, sla = _severity_and_sla(decision); description=_description(decision,action,evidence,sla,severity); table=os.getenv("SERVICENOW_TABLE","incident")
    score=float(decision.get("final_score",decision.get("risk",0)) or 0); urgency="1" if score>=85 else "2" if score>=40 else "3"
    payload={"short_description":description.splitlines()[0][:160],"description":description,"urgency":urgency,"impact":urgency}
    finding_field=os.getenv("SERVICENOW_FINDING_FIELD",""); idem_field=os.getenv("SERVICENOW_IDEMPOTENCY_FIELD","")
    if finding_field: payload[finding_field]=str(decision.get("finding_id") or decision.get("findingId") or action.get("actionId"))
    if idem_field: payload[idem_field]=idem
    headers={"Accept":"application/json","Content-Type":"application/json","X-AegisScan-Idempotency-Key":idem}; auth=None if token else (username,password)
    if token: headers["Authorization"]=f"Bearer {token}"
    async with httpx.AsyncClient(timeout=20,follow_redirects=True,headers=headers,auth=auth) as client:
        response=await client.post(f"{base}/api/now/table/{table}",json=payload); response.raise_for_status(); wrapper=response.json()
    data=wrapper.get("result",wrapper); sys_id=data.get("sys_id")
    return {"status":"created","provider":"servicenow","external_id":sys_id,"external_url":f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}" if sys_id else None,"response":data}


async def _create_provider(provider: str, decision: dict[str, Any], action: dict[str, Any], evidence: list[dict[str, Any]], idem: str) -> dict[str, Any]:
    return await (_create_jira if provider == "jira" else _create_servicenow)(decision, action, evidence, idem)


async def create_case(*, decision: dict[str, Any], owner: str, actor: str, idempotency_key: str, providers: list[str] | None = None, evidence: list[dict[str, Any]] | None = None, sla_hours: int | None = None, approved: bool = False) -> dict[str, Any]:
    initialize_itsm_store(); evidence=evidence or []; providers=list(dict.fromkeys(p.strip().lower() for p in (providers or list(PROVIDERS))))
    if not providers or any(p not in PROVIDERS for p in providers): raise ValueError("providers must contain only jira and/or servicenow")
    existing = await get_case_by_idempotency(idempotency_key)
    if existing: return existing
    decision=dict(decision); severity, computed_sla=_severity_and_sla(decision); computed_sla=sla_hours or computed_sla
    score=float(decision.get("final_score",decision.get("risk",0)) or 0); decision.setdefault("risk",int(round(score))); decision.setdefault("confidence",int(round(float(decision.get("confidence",0) or 0)*100)))
    action=create_action(decision,owner,computed_sla,actor,idempotency_key=idempotency_key)
    if approved: action=transition(action["actionId"],"approved",actor,"AADA approval recorded")
    request_hash=_request_hash(decision,evidence)
    for provider in providers:
        record=_get_or_create_record(action["actionId"],provider,idempotency_key,request_hash)
        if record.get("external_id"): continue
        if not _configured(provider):
            _update_record(record["record_id"],integration_state="not_configured",last_error=f"{provider} credentials are not configured"); _audit(action["actionId"],"itsm.provider_not_configured",actor,f"{provider} is not configured"); continue
        _update_record(record["record_id"],integration_state="creating",attempt_count=record["attempt_count"]+1,last_error=None)
        try:
            result=await _create_provider(provider,decision,action,evidence,idempotency_key)
            _update_record(record["record_id"],integration_state=result["status"],external_state="created",external_id=result.get("external_id"),external_url=result.get("external_url"),response=result.get("response") or {},last_error=None)
            _audit(action["actionId"],"itsm.created",actor,f"Created {provider} remediation ticket",{"provider":provider,"external_id":result.get("external_id")})
        except Exception as exc:
            _update_record(record["record_id"],integration_state="sync_error",last_error=f"{type(exc).__name__}: {exc}"); _audit(action["actionId"],"itsm.create_failed",actor,f"Failed to create {provider} remediation ticket",{"provider":provider,"error":type(exc).__name__})
    case=get_case(action["actionId"])
    if approved and case["all_required_created"]:
        transition(action["actionId"],"assigned",actor,"All required ITSM records created")
        transition(action["actionId"],"in_progress",actor,"Remediation work opened across all required ITSM records")
        await _sync_external_states(action["actionId"],"in_progress",actor,"Remediation work opened")
    return get_case(action["actionId"])


async def get_case_by_idempotency(idempotency_key: str) -> dict[str, Any] | None:
    initialize_itsm_store(); pool=_db(); conn=pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT action_id FROM remediation_integration_records WHERE idempotency_key=%s LIMIT 1",(idempotency_key,)); row=cur.fetchone()
            return get_case(row[0]) if row else None
    finally: pool.putconn(conn)


def get_case(action_id: str) -> dict[str, Any] | None:
    action=get_action(action_id)
    if action is None: return None
    initialize_itsm_store(); pool=_db(); conn=pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT record_id,action_id,provider,idempotency_key,request_hash,external_id,external_url,integration_state,external_state,response,last_error,attempt_count,validation,created_at,updated_at FROM remediation_integration_records WHERE action_id=%s ORDER BY provider",(action_id,)); records=[_record_dict(_row(r)) for r in cur.fetchall()]
    finally: pool.putconn(conn)
    return {"action":action,"integrations":records,"required_providers":list(PROVIDERS),"all_required_created":all(any(r["provider"]==p and r.get("external_id") for r in records) for p in PROVIDERS),"all_required_synced":all(any(r["provider"]==p and r.get("external_id") and r.get("external_state")==action["state"] for r in records) for p in PROVIDERS),"idempotency_keys":sorted({r["idempotency_key"] for r in records})}


async def sync_case(action_id: str, actor: str, providers: list[str] | None = None) -> dict[str, Any]:
    case=get_case(action_id)
    if not case: raise KeyError(action_id)
    requested=providers or list(PROVIDERS); action=case["action"]
    decision={"decisionId":action["decisionId"],"label":action["title"],"final_score":action["riskBefore"],"confidence":action["confidenceBefore"]/100}
    for rec in case["integrations"]:
        if rec["provider"] not in requested or rec.get("external_id") or not _configured(rec["provider"]): continue
        _update_record(rec["record_id"],integration_state="creating",attempt_count=rec["attempt_count"]+1,last_error=None)
        try:
            result=await _create_provider(rec["provider"],decision,action,[],rec["idempotency_key"]); _update_record(rec["record_id"],integration_state=result["status"],external_state="created",external_id=result.get("external_id"),external_url=result.get("external_url"),response=result.get("response") or {},last_error=None); _audit(action_id,"itsm.sync",actor,f"Created missing {rec['provider']} integration")
        except Exception as exc: _update_record(rec["record_id"],integration_state="sync_error",last_error=f"{type(exc).__name__}: {exc}")
    case=get_case(action_id)
    if action["state"]=="approved" and case["all_required_created"]:
        transition(action_id,"assigned",actor,"All required ITSM records are now created")
        transition(action_id,"in_progress",actor,"Remediation work resumed after ITSM synchronization")
        await _sync_external_states(action_id,"in_progress",actor,"Remediation work resumed")
    return get_case(action_id)


async def transition_case(action_id: str, target_state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    case=get_case(action_id)
    if not case: raise KeyError(action_id)
    if target_state=="verified": raise ValueError("verified is only reachable through successful remediation verification")
    if target_state in {"assigned","in_progress","awaiting_revalidation"} and not case["all_required_created"]:
        raise ValueError("All required ITSM providers must have an external ticket before active remediation states")
    updated=transition(action_id,target_state,actor,note)
    await _sync_external_states(action_id,target_state,actor,note)
    return get_case(action_id)


async def verify_case(action_id: str, actor: str, candidate: dict[str, Any], tools: list[str] | None = None, timeout: int = 180) -> dict[str, Any]:
    case=get_case(action_id)
    if not case: raise KeyError(action_id)
    action=case["action"]
    if action["state"]=="in_progress": transition(action_id,"awaiting_revalidation",actor,"Automatic remediation revalidation started")
    elif action["state"]!="awaiting_revalidation": raise ValueError(f"Action must be in_progress or awaiting_revalidation, got {action['state']}")
    result=await RemediationValidationSuite().validate_workspace(candidate,tools=tools,timeout=timeout)
    before=float(candidate.get("risk_before",action.get("riskBefore",0))); after=float(candidate.get("risk_after",before)); result["risk_diff"]=RemediationValidationSuite.compare_scores(before,after)
    passed=bool(result.get("passed")) and not result["risk_diff"].get("regressed")
    target="verified" if passed else "in_progress"
    if passed: updated=transition(action_id,"verified",actor,"Real validation passed; remediation verified",verification_context=True)
    else: updated=transition(action_id,"in_progress",actor,"Validation failed or risk regressed; remediation reopened")
    pool=_db(); conn=pool.getconn()
    try:
        with conn.cursor() as cur: cur.execute("UPDATE remediation_integration_records SET validation=%s, updated_at=%s WHERE action_id=%s",(json.dumps(result),_now(),action_id)); conn.commit()
    finally: pool.putconn(conn)
    await _sync_external_states(action_id,target,actor,json.dumps(result.get("summary",{})))
    _audit(action_id,"itsm.verified" if passed else "itsm.reopened",actor,"Remediation verification decision recorded",{"passed":passed,"risk_diff":result["risk_diff"]})
    return {"action":updated,"validation":result,"case":get_case(action_id)}


async def _sync_external_states(action_id: str, state: str, actor: str, note: str | None) -> None:
    case=get_case(action_id)
    if not case: return
    for rec in case["integrations"]:
        if not rec.get("external_id"): continue
        try:
            if rec["provider"]=="jira": await _jira_transition(rec["external_id"],state)
            else: await _servicenow_transition(rec["external_id"],state,note)
            _update_record(rec["record_id"],integration_state="synced",external_state=state,last_error=None)
            _audit(action_id,"itsm.state_synced",actor,f"Synchronized {rec['provider']} ticket to {state}",{"provider":rec["provider"],"external_id":rec["external_id"]})
        except Exception as exc:
            _update_record(rec["record_id"],integration_state="sync_error",last_error=f"{type(exc).__name__}: {exc}")
            _audit(action_id,"itsm.state_sync_failed",actor,f"Failed to synchronize {rec['provider']} ticket",{"provider":rec["provider"],"error":type(exc).__name__})


async def _jira_transition(issue_key: str, state: str) -> None:
    base=os.getenv("JIRA_BASE_URL","").rstrip("/"); token=os.getenv("JIRA_API_TOKEN"); email=os.getenv("JIRA_USER_EMAIL")
    if not all((base,token,email)): raise RuntimeError("Jira credentials are not configured")
    wanted={"pending":os.getenv("JIRA_STATUS_PENDING","To Do"),"approved":os.getenv("JIRA_STATUS_APPROVED","In Progress"),"assigned":os.getenv("JIRA_STATUS_ASSIGNED","In Progress"),"in_progress":os.getenv("JIRA_STATUS_IN_PROGRESS","In Progress"),"awaiting_revalidation":os.getenv("JIRA_STATUS_REVALIDATION","In Review"),"verified":os.getenv("JIRA_STATUS_VERIFIED","Done"),"rejected":os.getenv("JIRA_STATUS_REJECTED","Won't Do"),"deferred":os.getenv("JIRA_STATUS_DEFERRED","To Do")}.get(state,"In Progress")
    async with httpx.AsyncClient(timeout=20,auth=(email,token),headers={"Accept":"application/json","Content-Type":"application/json"}) as client:
        response=await client.get(f"{base}/rest/api/3/issue/{issue_key}/transitions"); response.raise_for_status(); data=response.json(); match=next((str(x.get("id")) for x in data.get("transitions",[]) if str(x.get("to",{}).get("name","")).lower()==wanted.lower()),None)
        if not match: raise RuntimeError(f"No Jira transition available to '{wanted}'")
        update=await client.post(f"{base}/rest/api/3/issue/{issue_key}/transitions",json={"transition":{"id":match}}); update.raise_for_status()


async def _servicenow_transition(sys_id: str, state: str, note: str | None) -> None:
    base=os.getenv("SERVICENOW_BASE_URL","").rstrip("/"); table=os.getenv("SERVICENOW_TABLE","incident"); token=os.getenv("SERVICENOW_API_TOKEN"); username=os.getenv("SERVICENOW_USERNAME"); password=os.getenv("SERVICENOW_PASSWORD")
    if not base or not (token or (username and password)): raise RuntimeError("ServiceNow credentials are not configured")
    headers={"Accept":"application/json","Content-Type":"application/json"}; auth=None if token else (username,password)
    if token: headers["Authorization"]=f"Bearer {token}"
    mapping={"pending":os.getenv("SERVICENOW_STATE_PENDING","1"),"approved":os.getenv("SERVICENOW_STATE_APPROVED","2"),"assigned":os.getenv("SERVICENOW_STATE_ASSIGNED","2"),"in_progress":os.getenv("SERVICENOW_STATE_IN_PROGRESS","2"),"awaiting_revalidation":os.getenv("SERVICENOW_STATE_REVALIDATION","2"),"verified":os.getenv("SERVICENOW_STATE_VERIFIED","7"),"rejected":os.getenv("SERVICENOW_STATE_REJECTED","8"),"deferred":os.getenv("SERVICENOW_STATE_DEFERRED","3")}
    async with httpx.AsyncClient(timeout=20,headers=headers,auth=auth) as client:
        response=await client.patch(f"{base}/api/now/table/{table}/{sys_id}",json={"state":mapping.get(state,"2"),"comments":note or f"AegisScan lifecycle state: {state}"}); response.raise_for_status()


get_lifecycle = get_case
create_action_and_ticket = None

async def transition_with_ticket(action_id: str, target_state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    return await transition_case(action_id, target_state, actor, note)

async def validate_and_verify(action_id: str, actor: str, *, candidate: dict[str, Any], tools: list[str] | None = None, timeout: int = 180) -> dict[str, Any]:
    return await verify_case(action_id, actor, candidate, tools=tools, timeout=timeout)

async def create_action_and_ticket(*, decision: dict[str, Any], owner: str, sla_hours: int, actor: str, provider: str, evidence: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return await create_case(decision=decision, owner=owner, actor=actor, idempotency_key=f"legacy-{decision.get('decisionId','unknown')}-{provider}", providers=[provider], evidence=evidence or [], sla_hours=sla_hours, approved=False)
