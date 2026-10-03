"""Intent contract for the first anonymous fixture transport probe, not a solver."""
from __future__ import annotations

from uuid import UUID

CAPABILITY_ID = 'burp.mcp.gateway'
LAB_DEFINITION_ID = 'bac-orders-v1'


def validate_burp_probe_options(options: dict) -> dict:
    if not isinstance(options, dict) or set(options) - {'provider_decision_ref', 'lab_definition_id'}:
        raise ValueError('Burp probe accepts provider_decision_ref and lab_definition_id only')
    try:
        decision = str(UUID(options.get('provider_decision_ref', '')))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError('provider_decision_ref must reference a current approval UUID') from exc
    lab = options.get('lab_definition_id', LAB_DEFINITION_ID)
    if lab != LAB_DEFINITION_ID:
        raise ValueError('Only the pinned BAC fixture transport probe is supported')
    return {'provider_decision_ref': decision, 'lab_definition_id': lab}
