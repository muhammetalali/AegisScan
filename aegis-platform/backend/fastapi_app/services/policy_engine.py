from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from django.db import connection, transaction

DEFAULT_POLICIES: list[dict[str, Any]] = [
    {"id":"critical-production","version":1,"name":"Critical production risk","enabled":True,"priority":100,"when":{"risk_gte":90,"environment":"production"},"actions":{"approval_role":"ciso","approval_count":2,"sla_hours":2,"escalate_after_minutes":60,"escalation_targets":["security_manager","ciso"]}},
    {"id":"critical","version":1,"name":"Critical risk","enabled":True,"priority":90,"when":{"risk_gte":90},"actions":{"approval_role":"ciso","approval_count":1,"sla_hours":4,"escalate_after_minutes":120,"escalation_targets":["security_manager","ciso"]}},
    {"id":"high","version":1,"name":"High risk","enabled":True,"priority":80,"when":{"risk_gte":75},"actions":{"approval_role":"security_manager","approval_count":1,"sla_hours":24,"escalate_after_minutes":360,"escalation_targets":["security_manager"]}},
    {"id":"medium","version":1,"name":"Medium risk","enabled":True,"priority":60,"when":{"risk_gte":45},"actions":{"approval_role":"analyst","approval_count":1,"sla_hours":72,"escalate_after_minutes":1440,"escalation_targets":["security_manager"]}},
    {"id":"low","version":1,"name":"Low risk","enabled":True,"priority":10,"when":{},"actions":{"approval_role":"none","approval_count":0,"sla_hours":168,"escalate_after_minutes":2880,"escalation_targets":["analyst"]}},
]

_schema_ready = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def initialize_policy_store() -> None:
    global _schema_ready
    # Schema and seed ownership belongs to Django migration 0007.
    _schema_ready = True


def list_policies() -> list[dict[str, Any]]:
    initialize_policy_store()
    with connection.cursor() as cur:
        cur.execute("SELECT policy_id,version,name,enabled,priority,conditions,actions,created_by,created_at FROM assurance_policies ORDER BY priority DESC, policy_id, version DESC")
        result=[]
        for row in cur.fetchall():
            policy_id,version,name,enabled,priority,conditions,actions,created_by,created_at=row
            result.append({"id":policy_id,"version":version,"name":name,"enabled":enabled,"priority":priority,"when":conditions if isinstance(conditions,dict) else json.loads(conditions),"actions":actions if isinstance(actions,dict) else json.loads(actions),"createdBy":created_by,"createdAt":created_at.isoformat()})
        return result


def save_policy(policy: dict[str, Any], actor: str, require_existing: bool | None = None) -> dict[str, Any]:
    initialize_policy_store()
    with transaction.atomic():
        with connection.cursor() as cur:
            if connection.vendor == "postgresql":
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (policy["id"],))
            cur.execute("SELECT COALESCE(MAX(version),0) FROM assurance_policies WHERE policy_id=%s", (policy["id"],))
            current_version = int(cur.fetchone()[0])
            if require_existing is False and current_version:
                raise FileExistsError(policy["id"])
            if require_existing is True and not current_version:
                raise KeyError(policy["id"])
            version=current_version+1
            now=_now()
            item={**policy,"version":version,"createdBy":actor,"createdAt":now.isoformat()}
            cur.execute("INSERT INTO assurance_policies(policy_id,version,name,enabled,priority,conditions,actions,created_by,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (item["id"],version,item["name"],item.get("enabled",True),item.get("priority",50),json.dumps(item.get("when",{})),json.dumps(item.get("actions",{})),actor,now))
            return item


def _matches(policy: dict[str, Any], action: dict[str, Any]) -> bool:
    cond = policy.get("when", {}); risk=int(action.get("riskBefore",0) or 0); priority=int(action.get("priority",0) or 0)
    if "risk_gte" in cond and risk < int(cond["risk_gte"]): return False
    if "risk_lte" in cond and risk > int(cond["risk_lte"]): return False
    if "priority_gte" in cond and priority < int(cond["priority_gte"]): return False
    if "environment" in cond and str(action.get("environment", "")).lower() != str(cond["environment"]).lower(): return False
    return True


def select_policy(action: dict[str, Any], policies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    candidates=[p for p in (policies if policies is not None else list_policies()) if p.get("enabled",True) and _matches(p,action)]
    return max(candidates,key=lambda p:(int(p.get("priority",0)),int(p.get("version",0)))) if candidates else (policies[-1] if policies else DEFAULT_POLICIES[-1])


def evaluate_policy(action: dict[str, Any], policies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    policy=select_policy(action,policies); rules=policy.get("actions",{})
    return {"policyId":policy["id"],"policyVersion":policy.get("version",1),"policyName":policy["name"],"approvalRole":rules.get("approval_role","none"),"approvalCount":int(rules.get("approval_count",0)),"slaHours":int(rules.get("sla_hours",168)),"escalateAfterMinutes":int(rules.get("escalate_after_minutes",2880)),"escalationTargets":list(rules.get("escalation_targets",[])),"evaluatedAt":datetime.now(timezone.utc).isoformat(),"rationale":f"Selected {policy['name']} (v{policy.get('version',1)}) from risk/priority/context."}
