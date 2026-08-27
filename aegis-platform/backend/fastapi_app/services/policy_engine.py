from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

DEFAULT_POLICIES: list[dict[str, Any]] = [
    {"id":"critical-production","version":1,"name":"Critical production risk","enabled":True,"priority":100,"when":{"risk_gte":90,"environment":"production"},"actions":{"approval_role":"ciso","approval_count":2,"sla_hours":2,"escalate_after_minutes":60,"escalation_targets":["security_manager","ciso"]}},
    {"id":"critical","version":1,"name":"Critical risk","enabled":True,"priority":90,"when":{"risk_gte":90},"actions":{"approval_role":"ciso","approval_count":1,"sla_hours":4,"escalate_after_minutes":120,"escalation_targets":["security_manager","ciso"]}},
    {"id":"high","version":1,"name":"High risk","enabled":True,"priority":80,"when":{"risk_gte":75},"actions":{"approval_role":"security_manager","approval_count":1,"sla_hours":24,"escalate_after_minutes":360,"escalation_targets":["security_manager"]}},
    {"id":"medium","version":1,"name":"Medium risk","enabled":True,"priority":60,"when":{"risk_gte":45},"actions":{"approval_role":"analyst","approval_count":1,"sla_hours":72,"escalate_after_minutes":1440,"escalation_targets":["security_manager"]}},
    {"id":"low","version":1,"name":"Low risk","enabled":True,"priority":10,"when":{},"actions":{"approval_role":"none","approval_count":0,"sla_hours":168,"escalate_after_minutes":2880,"escalation_targets":["analyst"]}},
]


def _matches(policy: dict[str, Any], action: dict[str, Any]) -> bool:
    cond = policy.get("when", {})
    risk = int(action.get("riskBefore", 0) or 0)
    if "risk_gte" in cond and risk < int(cond["risk_gte"]): return False
    if "risk_lte" in cond and risk > int(cond["risk_lte"]): return False
    if "priority_gte" in cond and int(action.get("priority", 0) or 0) < int(cond["priority_gte"]): return False
    if "environment" in cond and str(action.get("environment", "")).lower() != str(cond["environment"]).lower(): return False
    return True


def select_policy(action: dict[str, Any], policies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    candidates = [p for p in (policies or DEFAULT_POLICIES) if p.get("enabled", True) and _matches(p, action)]
    return max(candidates, key=lambda p: (int(p.get("priority", 0)), int(p.get("version", 0)))) if candidates else DEFAULT_POLICIES[-1]


def evaluate_policy(action: dict[str, Any], policies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    policy = select_policy(action, policies)
    rules = policy.get("actions", {})
    return {"policyId": policy["id"], "policyVersion": policy.get("version", 1), "policyName": policy["name"], "approvalRole": rules.get("approval_role", "none"), "approvalCount": int(rules.get("approval_count", 0)), "slaHours": int(rules.get("sla_hours", 168)), "escalateAfterMinutes": int(rules.get("escalate_after_minutes", 2880)), "escalationTargets": list(rules.get("escalation_targets", [])), "evaluatedAt": datetime.now(timezone.utc).isoformat(), "rationale": f"Selected {policy['name']} (v{policy.get('version',1)}) from risk/priority/context."}
