from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .policy_engine import evaluate_policy, list_policies


def _impact(current: dict[str, Any], proposed: dict[str, Any]) -> dict[str, Any]:
    def delta(key: str) -> int:
        return int(proposed.get(key, 0) or 0) - int(current.get(key, 0) or 0)
    approval_delta = delta('approvalCount')
    sla_delta = delta('slaHours')
    escalation_delta = delta('escalationLevel')
    return {
        'approvalDelta': approval_delta,
        'slaDeltaHours': sla_delta,
        'escalationDelta': escalation_delta,
        'approvalPressure': 'higher' if approval_delta > 0 else 'lower' if approval_delta < 0 else 'unchanged',
        'timePressure': 'higher' if sla_delta < 0 else 'lower' if sla_delta > 0 else 'unchanged',
        'governanceImpact': 'hardened' if approval_delta > 0 or sla_delta < 0 or escalation_delta > 0 else 'relaxed' if approval_delta < 0 or sla_delta > 0 or escalation_delta < 0 else 'unchanged',
    }


def simulate_policy(action: dict[str, Any], proposed_policy: dict[str, Any]) -> dict[str, Any]:
    current = evaluate_policy(action, list_policies())
    proposed = evaluate_policy(action, [proposed_policy])
    impact = _impact({**current, 'escalationLevel': 0}, {**proposed, 'escalationLevel': 0})
    return {
        'actionId': action.get('actionId'),
        'current': current,
        'proposed': proposed,
        'impact': impact,
        'safeToPublish': proposed.get('approvalCount', 0) >= 0 and proposed.get('slaHours', 0) > 0,
        'simulatedAt': datetime.now(timezone.utc).isoformat(),
    }
