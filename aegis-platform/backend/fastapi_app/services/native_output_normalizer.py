from __future__ import annotations

import json
from typing import Any

from . import native_output_normalizer_core as _core

# Preserve the historical module surface while extending one browser observation
# contract. Existing callers (including focused tests that import private helpers)
# continue to resolve the same implementation objects from the frozen core.
for _name in dir(_core):
    if _name.startswith('__') or _name == 'normalize_native_output':
        continue
    globals()[_name] = getattr(_core, _name)

_ALLOWED_MESSAGE_DIRECTIONS = {'send', 'receive'}
_ALLOWED_MESSAGE_TYPES = {
    'array', 'boolean', 'bigint', 'function', 'null', 'number', 'object',
    'string', 'symbol', 'undefined', 'unknown',
}
_ALLOWED_MESSAGE_STATUSES = {'observed', 'not-observed'}
_SPECIAL_MESSAGE_ORIGINS = {'*', '/', 'null', 'same-origin-default'}


def _safe_message_origin(value: Any) -> str:
    origin = str(value or '')[:512]
    if origin in _SPECIAL_MESSAGE_ORIGINS or origin.startswith(('http://', 'https://')):
        return origin
    return 'null'


def _normalize_web_messaging_assessment(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict) or item.get('kind') != 'browser-web-messaging-assessment':
        return None

    records: list[dict[str, Any]] = []
    rows = item.get('records') if isinstance(item.get('records'), list) else []
    for row in rows[:128]:
        if not isinstance(row, dict):
            continue
        direction = str(row.get('direction') or '').lower()
        if direction not in _ALLOWED_MESSAGE_DIRECTIONS:
            continue
        data_type = str(row.get('data_type') or 'unknown').lower()
        if data_type not in _ALLOWED_MESSAGE_TYPES:
            data_type = 'unknown'
        keys = row.get('data_keys') if isinstance(row.get('data_keys'), list) else []
        records.append({
            'direction': direction,
            'peer_origin': _safe_message_origin(row.get('peer_origin')),
            'same_origin_peer': row.get('same_origin_peer') is True,
            'data_type': data_type,
            'data_keys': sorted({
                str(value)[:80]
                for value in keys[:32]
                if isinstance(value, str)
                and value
                and not any(ch in value for ch in '\r\n\x00')
            })[:32],
        })

    status = str(item.get('status') or '')
    if status not in _ALLOWED_MESSAGE_STATUSES:
        status = 'not-observed'
    limitations = item.get('limitations') if isinstance(item.get('limitations'), list) else []
    return {
        'kind': 'browser-web-messaging-assessment',
        'wstg_id': 'WSTG-CLNT-11',
        'observation_only': True,
        'final_decision': False,
        'status': status,
        'listener_count': _core._positive_int(item.get('listener_count'), 100000),
        'send_count': _core._positive_int(item.get('send_count'), 100000),
        'receive_count': _core._positive_int(item.get('receive_count'), 100000),
        'metadata_record_count': len(records),
        'wildcard_target_count': _core._positive_int(item.get('wildcard_target_count'), 128),
        'explicit_target_origin_count': _core._positive_int(
            item.get('explicit_target_origin_count'), 128
        ),
        'cross_origin_receive_count': _core._positive_int(
            item.get('cross_origin_receive_count'), 128
        ),
        'wildcard_target_observed': item.get('wildcard_target_observed') is True,
        'cross_origin_receive_observed': item.get('cross_origin_receive_observed') is True,
        # These three fields are server-owned fail-closed guarantees. Scanner JSON
        # cannot elevate passive telemetry into proof or claim payload collection.
        'origin_validation_confirmed': False,
        'payload_values_captured': False,
        'synthetic_cross_origin_messages_injected': False,
        'limitations': [
            str(value)[:500]
            for value in limitations[:4]
            if isinstance(value, str)
        ],
        'records': records,
    }


def normalize_native_output(capability_id: str, stdout: str) -> dict[str, Any]:
    result = _core.normalize_native_output(capability_id, stdout)
    if capability_id != 'browser.spa-discovery':
        return result

    try:
        data = json.loads(stdout or '{}')
    except (TypeError, ValueError, json.JSONDecodeError):
        return result
    if not isinstance(data, dict):
        return result
    raw_observations = data.get('observations')
    if not isinstance(raw_observations, list):
        return result

    # Enrich the pre-existing summary contract with the received-message counter.
    raw_summary = next(
        (
            item for item in raw_observations
            if isinstance(item, dict) and item.get('kind') == 'browser-spa-summary'
        ),
        None,
    )
    if isinstance(raw_summary, dict):
        for observation in result.get('observations', []):
            if isinstance(observation, dict) and observation.get('kind') == 'browser-spa-summary':
                observation['post_message_receive_count'] = _core._positive_int(
                    raw_summary.get('post_message_receive_count'), 100000
                )
                break

    for item in raw_observations:
        assessment = _normalize_web_messaging_assessment(item)
        if assessment is not None:
            result.setdefault('observations', []).append(assessment)
            break

    observations = [
        item for item in result.get('observations', [])[:2000]
        if isinstance(item, dict)
    ]
    result['observations'] = observations
    result['count'] = len(observations)
    return result
