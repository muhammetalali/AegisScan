from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Mapping


class OASTProofConfigurationError(RuntimeError):
    pass


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)


def _signing_key() -> bytes:
    raw = os.getenv('OAST_TOKEN_SIGNING_KEY', '')
    encoded = raw.encode('utf-8')
    if len(encoded) < 32:
        raise OASTProofConfigurationError(
            'OAST_TOKEN_SIGNING_KEY must contain at least 32 bytes.'
        )
    return encoded


def _proof_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        'session_id': str(payload['session_id']),
        'execution_id': str(payload['execution_id']),
        'target_sha256': str(payload['target_sha256']),
        'interaction_ids': [str(item) for item in payload['interaction_ids']],
        'evidence_ids': [str(item) for item in payload['evidence_ids']],
        'protocols': sorted(str(item) for item in payload['protocols']),
        'callback_count': int(payload['callback_count']),
    }


def sign_ssrf_oast_proof(payload: Mapping[str, Any]) -> str:
    normalized = _proof_payload(payload)
    return hmac.new(
        _signing_key(),
        ('ssrf-oast-proof:' + _canonical_json(normalized)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def verify_ssrf_oast_proof(payload: Mapping[str, Any]) -> bool:
    try:
        normalized = _proof_payload(payload)
        supplied = str(payload['proof_hmac'])
    except (KeyError, TypeError, ValueError):
        return False
    if (
        not normalized['session_id']
        or not normalized['execution_id']
        or len(normalized['target_sha256']) != 64
        or not normalized['interaction_ids']
        or not normalized['evidence_ids']
        or len(normalized['interaction_ids']) != len(normalized['evidence_ids'])
        or normalized['callback_count'] != len(normalized['interaction_ids'])
        or any(protocol not in {'dns', 'http'} for protocol in normalized['protocols'])
        or len(supplied) != 64
    ):
        return False
    expected = sign_ssrf_oast_proof(normalized)
    return hmac.compare_digest(supplied, expected)


__all__ = [
    'OASTProofConfigurationError',
    'sign_ssrf_oast_proof',
    'verify_ssrf_oast_proof',
]
