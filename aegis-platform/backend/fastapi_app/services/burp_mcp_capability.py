"""Intent contract for the transport probe and pinned BAC observations."""
from __future__ import annotations

from uuid import UUID

CAPABILITY_ID = 'burp.mcp.gateway'
LAB_DEFINITION_ID = 'bac-orders-v1'


def validate_burp_probe_options(options: dict) -> dict:
    if not isinstance(options, dict) or set(options) - {'provider_decision_ref', 'lab_definition_id', 'mode', 'provider_credential_ref'}:
        raise ValueError('Unsupported Burp execution option')
    try:
        decision = str(UUID(options.get('provider_decision_ref', '')))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError('provider_decision_ref must reference a current approval UUID') from exc
    lab = options.get('lab_definition_id', LAB_DEFINITION_ID)
    if lab != LAB_DEFINITION_ID:
        raise ValueError('Only the pinned BAC fixture transport probe is supported')
    result = {'provider_decision_ref': decision, 'lab_definition_id': lab}
    mode = options.get('mode', 'transport_probe')
    if not isinstance(mode, str) or mode not in {'transport_probe', 'lab_sequence'}:
        raise ValueError('Only the transport probe or pinned BAC GET sequence is supported')
    if 'mode' in options:
        result['mode'] = mode
    if 'provider_credential_ref' in options:
        if mode != 'lab_sequence':
            raise ValueError('Explicit provider credential selection is for lab_sequence only')
        try:
            result['provider_credential_ref'] = str(UUID(options['provider_credential_ref']))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('provider_credential_ref must be a credential UUID') from exc
    return result
