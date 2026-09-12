from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from .capability_registry import Capability, list_capabilities
from .native_packaging import PACKAGED_NATIVE_CAPABILITIES
from .native_tool_runtime import NATIVE_TOOL_SPECS

Depth = Literal['quick', 'standard', 'deep', 'comprehensive']

_RISK_WEIGHT = {
    'passive': 0,
    'active-low': 10,
    'active-medium': 20,
    'active-high': 30,
}
_DEPTH_LIMIT = {
    'quick': 10,
    'standard': 20,
    'deep': 30,
    'comprehensive': 100,
}


@dataclass(frozen=True)
class PlannedCapability:
    capability_id: str
    tool: str
    category: str
    risk: str
    execution_ready: bool
    reason: str
    order: int

    def public_dict(self) -> dict:
        return asdict(self)


def _execution_ready(capability: Capability) -> bool:
    if capability.id not in NATIVE_TOOL_SPECS:
        return True
    return capability.id in PACKAGED_NATIVE_CAPABILITIES


def plan_capabilities(asset_type: str, depth: Depth = 'standard') -> list[PlannedCapability]:
    if depth not in _DEPTH_LIMIT:
        raise ValueError(f'Unsupported capability planning depth: {depth}')
    risk_limit = _DEPTH_LIMIT[depth]
    candidates = [cap for cap in list_capabilities() if asset_type in cap.asset_types]
    candidates.sort(
        key=lambda item: (
            not _execution_ready(item),
            _RISK_WEIGHT.get(item.risk, 999),
            item.category,
            item.id,
        )
    )
    plan: list[PlannedCapability] = []
    for capability in candidates:
        ready = _execution_ready(capability)
        risk_weight = _RISK_WEIGHT.get(capability.risk, 999)
        if risk_weight > risk_limit:
            continue
        plan.append(
            PlannedCapability(
                capability_id=capability.id,
                tool=capability.tool,
                category=capability.category,
                risk=capability.risk,
                execution_ready=ready,
                reason=(
                    'packaged and eligible for governed execution'
                    if ready
                    else 'adapter registered; scanner image packaging proof pending'
                ),
                order=len(plan) + 1,
            )
        )
    return plan


def planning_summary(asset_type: str, depth: Depth = 'standard') -> dict:
    plan = plan_capabilities(asset_type, depth)
    ready = [item for item in plan if item.execution_ready]
    pending = [item for item in plan if not item.execution_ready]
    return {
        'asset_type': asset_type,
        'depth': depth,
        'total': len(plan),
        'ready': len(ready),
        'pending_packaging': len(pending),
        'plan': [item.public_dict() for item in plan],
    }
