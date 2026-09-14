from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

_MAX_RECORDS = 128
_MAX_KEYS = 32
_ALLOWED_DIRECTIONS = {'send', 'receive'}
_ALLOWED_DATA_TYPES = {
    'array', 'boolean', 'bigint', 'function', 'null', 'number', 'object',
    'string', 'symbol', 'undefined', 'unknown',
}


def _canonical_origin(value: Any) -> str:
    raw = str(value or '').strip()
    if raw in {'*', '/', 'null', 'same-origin-default'}:
        return raw
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or '').lower().rstrip('.')
        if scheme not in {'http', 'https'} or not host:
            return ''
        port = parsed.port
    except (TypeError, ValueError):
        return ''
    default_port = 80 if scheme == 'http' else 443
    authority = host if port in {None, default_port} else f'{host}:{port}'
    return urlunsplit((scheme, authority, '', '', ''))


def _bounded_keys(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    keys = {
        str(item)[:80]
        for item in value[:_MAX_KEYS]
        if isinstance(item, str) and item and not any(ch in item for ch in '\r\n\x00')
    }
    return sorted(keys)[:_MAX_KEYS]


def normalize_web_message_record(raw: Any, *, target_origin: str) -> dict[str, Any] | None:
    """Normalize metadata-only postMessage telemetry without retaining payload values."""
    if not isinstance(raw, dict):
        return None
    direction = str(raw.get('direction') or '').lower()
    if direction not in _ALLOWED_DIRECTIONS:
        return None
    data_type = str(raw.get('data_type') or 'unknown').lower()
    if data_type not in _ALLOWED_DATA_TYPES:
        data_type = 'unknown'

    peer_origin = _canonical_origin(raw.get('peer_origin'))
    if not peer_origin:
        peer_origin = 'same-origin-default' if direction == 'send' else 'null'

    canonical_target = _canonical_origin(target_origin)
    same_origin_peer = bool(
        canonical_target
        and peer_origin not in {'*', '/', 'null', 'same-origin-default'}
        and peer_origin == canonical_target
    )
    return {
        'direction': direction,
        'peer_origin': peer_origin[:512],
        'same_origin_peer': same_origin_peer,
        'data_type': data_type,
        'data_keys': _bounded_keys(raw.get('data_keys')),
    }


def assess_web_messaging(
    records: Iterable[Any],
    *,
    target_origin: str,
    listener_count: int,
    sent_count: int,
    received_count: int,
) -> dict[str, Any]:
    """Build an observation-only WSTG-CLNT-11 assessment from passive browser telemetry.

    The assessment intentionally does not claim that a receiver validates event.origin:
    proving that requires handler-aware analysis or a governed active test. No synthetic
    cross-origin messages are injected here.
    """
    normalized: list[dict[str, Any]] = []
    for item in records:
        safe = normalize_web_message_record(item, target_origin=target_origin)
        if safe is not None:
            normalized.append(safe)
        if len(normalized) >= _MAX_RECORDS:
            break

    sends = [item for item in normalized if item['direction'] == 'send']
    receives = [item for item in normalized if item['direction'] == 'receive']
    wildcard_sends = [item for item in sends if item['peer_origin'] == '*']
    explicit_sends = [
        item for item in sends
        if item['peer_origin'] not in {'*', '/', 'null', 'same-origin-default'}
    ]
    cross_origin_receives = [
        item for item in receives
        if item['peer_origin'] not in {'null'} and not item['same_origin_peer']
    ]
    observed = bool(listener_count or sent_count or received_count or normalized)

    return {
        'kind': 'browser-web-messaging-assessment',
        'wstg_id': 'WSTG-CLNT-11',
        'observation_only': True,
        'final_decision': False,
        'status': 'observed' if observed else 'not-observed',
        'listener_count': max(0, int(listener_count or 0)),
        'send_count': max(0, int(sent_count or 0)),
        'receive_count': max(0, int(received_count or 0)),
        'metadata_record_count': len(normalized),
        'wildcard_target_count': len(wildcard_sends),
        'explicit_target_origin_count': len(explicit_sends),
        'cross_origin_receive_count': len(cross_origin_receives),
        'wildcard_target_observed': bool(wildcard_sends),
        'cross_origin_receive_observed': bool(cross_origin_receives),
        'origin_validation_confirmed': False,
        'payload_values_captured': False,
        'synthetic_cross_origin_messages_injected': False,
        'limitations': [
            'Receiver event.origin validation is not inferred from passive instrumentation.',
            'No synthetic cross-origin postMessage traffic is injected by this capability.',
        ],
        'records': normalized,
    }
