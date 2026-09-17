from __future__ import annotations

import json

import pytest

from fastapi_app.services.masscan_semantic_parity import compare_masscan_semantics, masscan_semantic_snapshot


def _dump(records):
    return json.dumps(records, separators=(',', ':'))


def test_semantic_snapshot_matches_finding_identity_and_ignores_ephemeral_fields():
    raw = _dump([
        {'ip': '172.31.1.10', 'timestamp': '1', 'ports': [
            {'port': 80, 'proto': 'tcp', 'status': 'open', 'reason': 'syn-ack', 'ttl': 64},
            {'port': '22', 'protocol': 'TCP', 'status': 'open', 'reason': 'syn-ack', 'ttl': 63},
        ]},
        {'ip': '172.31.1.10', 'timestamp': '2', 'ports': [{'port': 80, 'proto': 'tcp'}]},
    ])
    assert masscan_semantic_snapshot(raw) == {
        'observations': [
            {'ip': '172.31.1.10', 'protocol': 'tcp', 'port': 22},
            {'ip': '172.31.1.10', 'protocol': 'tcp', 'port': 80},
        ],
        'finding_count': 2,
    }


def test_semantic_parity_ignores_order_timestamp_reason_and_ttl():
    legacy = _dump([
        {'ip': '172.31.1.10', 'timestamp': '100', 'ports': [
            {'port': 80, 'proto': 'tcp', 'status': 'open', 'reason': 'syn-ack', 'ttl': 64},
            {'port': 22, 'proto': 'tcp', 'status': 'open', 'reason': 'syn-ack', 'ttl': 64},
        ]},
    ])
    candidate = _dump([
        {'ip': '172.31.1.10', 'timestamp': '999', 'ports': [
            {'port': 22, 'proto': 'TCP', 'status': 'open', 'reason': 'response', 'ttl': 32},
        ]},
        {'ip': '172.31.1.10', 'ports': [{'port': 80, 'protocol': 'tcp'}]},
    ])
    comparison = compare_masscan_semantics(legacy, candidate)
    assert comparison['equivalent'] is True
    assert comparison['legacy']['finding_count'] == 2


def test_semantic_parity_detects_finding_relevant_changes():
    legacy = _dump([{'ip': '172.31.1.10', 'ports': [{'port': 80, 'proto': 'tcp'}]}])
    candidate = _dump([{'ip': '172.31.1.10', 'ports': [{'port': 443, 'proto': 'tcp'}]}])
    comparison = compare_masscan_semantics(legacy, candidate)
    assert comparison['equivalent'] is False


def test_snapshot_accepts_empty_output_and_single_record_object():
    assert masscan_semantic_snapshot('')['finding_count'] == 0
    single = _dump({'ip': '10.0.0.1', 'ports': [{'port': 53, 'proto': 'udp'}]})
    assert masscan_semantic_snapshot(single)['observations'] == [
        {'ip': '10.0.0.1', 'protocol': 'udp', 'port': 53},
    ]


def test_snapshot_rejects_non_collection_json():
    with pytest.raises(ValueError, match='JSON object or array'):
        masscan_semantic_snapshot('"not-masscan"')
