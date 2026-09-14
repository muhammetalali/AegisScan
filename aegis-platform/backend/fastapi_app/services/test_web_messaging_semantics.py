from __future__ import annotations

from fastapi_app.services.web_messaging_semantics import (
    assess_web_messaging,
    normalize_web_message_record,
)


def test_web_message_record_keeps_shape_not_payload_values():
    raw = {
        'direction': 'send',
        'peer_origin': '*',
        'data_type': 'object',
        'data_keys': ['token', 'action', 'accountId'],
        'payload': 'super-secret-value',
        'value': {'token': 'do-not-retain'},
    }
    safe = normalize_web_message_record(raw, target_origin='https://app.example.test')
    assert safe == {
        'direction': 'send',
        'peer_origin': '*',
        'same_origin_peer': False,
        'data_type': 'object',
        'data_keys': ['accountId', 'action', 'token'],
    }
    assert 'super-secret-value' not in str(safe)
    assert 'do-not-retain' not in str(safe)


def test_web_message_assessment_is_observation_only_and_flags_wildcard_target():
    result = assess_web_messaging(
        [
            {
                'direction': 'send',
                'peer_origin': '*',
                'data_type': 'object',
                'data_keys': ['type'],
            },
            {
                'direction': 'receive',
                'peer_origin': 'https://partner.example.test',
                'data_type': 'string',
                'data_keys': [],
            },
        ],
        target_origin='https://app.example.test',
        listener_count=2,
        sent_count=1,
        received_count=1,
    )

    assert result['wstg_id'] == 'WSTG-CLNT-11'
    assert result['observation_only'] is True
    assert result['final_decision'] is False
    assert result['wildcard_target_observed'] is True
    assert result['wildcard_target_count'] == 1
    assert result['cross_origin_receive_observed'] is True
    assert result['origin_validation_confirmed'] is False
    assert result['payload_values_captured'] is False
    assert result['synthetic_cross_origin_messages_injected'] is False


def test_web_message_assessment_canonicalizes_same_origin_peer():
    result = assess_web_messaging(
        [{
            'direction': 'receive',
            'peer_origin': 'https://APP.EXAMPLE.TEST:443',
            'data_type': 'number',
            'data_keys': [],
        }],
        target_origin='https://app.example.test',
        listener_count=1,
        sent_count=0,
        received_count=1,
    )
    record = result['records'][0]
    assert record['peer_origin'] == 'https://app.example.test'
    assert record['same_origin_peer'] is True
    assert result['cross_origin_receive_count'] == 0
