from __future__ import annotations

import json
from typing import Any


def _records(raw_json: str) -> list[dict[str, Any]]:
    if not raw_json.strip():
        return []
    payload = json.loads(raw_json)
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        raise ValueError('Masscan output must be a JSON object or array')
    return [item for item in payload if isinstance(item, dict)]


def masscan_semantic_snapshot(raw_json: str) -> dict[str, Any]:
    observations: set[tuple[str, str, int]] = set()
    for record in _records(raw_json):
        ip = str(record.get('ip') or '').strip()
        ports = record.get('ports')
        if not isinstance(ports, list):
            continue
        for item in ports:
            if not isinstance(item, dict):
                continue
            try:
                port = int(item.get('port'))
            except (TypeError, ValueError):
                continue
            if port < 1 or port > 65535:
                continue
            protocol = str(item.get('proto') or item.get('protocol') or 'tcp').strip().lower()
            if not protocol:
                protocol = 'tcp'
            observations.add((ip, protocol, port))

    canonical = [
        {'ip': ip, 'protocol': protocol, 'port': port}
        for ip, protocol, port in sorted(observations, key=lambda item: (item[0], item[1], item[2]))
    ]
    return {
        'observations': canonical,
        'finding_count': len(canonical),
    }


def compare_masscan_semantics(legacy_json: str, candidate_json: str) -> dict[str, Any]:
    legacy = masscan_semantic_snapshot(legacy_json)
    candidate = masscan_semantic_snapshot(candidate_json)
    return {
        'schema': 'aegis.network-masscan-semantic-parity.v1',
        'equivalent': legacy == candidate,
        'legacy': legacy,
        'candidate': candidate,
    }
