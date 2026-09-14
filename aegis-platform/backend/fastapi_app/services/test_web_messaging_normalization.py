from __future__ import annotations

import json

from fastapi_app.services.native_output_normalizer import normalize_native_output


def test_web_messaging_normalizer_whitelists_metadata_and_drops_payloads():
    raw = json.dumps({
        'schema': 'aegis.browser-spa-discovery.v1',
        'observations': [
            {
                'kind': 'browser-spa-summary',
                'identity_ref': 'alice',
                'target_origin': 'https://app.example.test',
                'post_message_listener_count': 2,
                'post_message_send_count': 1,
                'post_message_receive_count': 1,
            },
            {
                'kind': 'browser-web-messaging-assessment',
                'wstg_id': 'attacker-controlled-id',
                'observation_only': False,
                'final_decision': True,
                'status': 'observed',
                'listener_count': 2,
                'send_count': 1,
                'receive_count': 1,
                'wildcard_target_count': 1,
                'explicit_target_origin_count': 0,
                'cross_origin_receive_count': 1,
                'wildcard_target_observed': True,
                'cross_origin_receive_observed': True,
                'origin_validation_confirmed': True,
                'payload_values_captured': True,
                'synthetic_cross_origin_messages_injected': True,
                'secret': 'assessment-secret-value',
                'records': [
                    {
                        'direction': 'send',
                        'peer_origin': '*',
                        'same_origin_peer': False,
                        'data_type': 'object',
                        'data_keys': ['token', 'action'],
                        'payload': 'do-not-retain-message-body',
                        'value': {'token': 'do-not-retain-token'},
                    },
                    {
                        'direction': 'receive',
                        'peer_origin': 'javascript:alert(1)',
                        'same_origin_peer': False,
                        'data_type': 'custom-secret-type',
                        'data_keys': ['event'],
                    },
                ],
                'limitations': ['passive telemetry only'],
            },
        ],
    })

    normalized = normalize_native_output('browser.spa-discovery', raw)
    summary = next(
        item for item in normalized['observations']
        if item['kind'] == 'browser-spa-summary'
    )
    assessment = next(
        item for item in normalized['observations']
        if item['kind'] == 'browser-web-messaging-assessment'
    )

    assert summary['post_message_receive_count'] == 1
    assert assessment['wstg_id'] == 'WSTG-CLNT-11'
    assert assessment['observation_only'] is True
    assert assessment['final_decision'] is False
    assert assessment['origin_validation_confirmed'] is False
    assert assessment['payload_values_captured'] is False
    assert assessment['synthetic_cross_origin_messages_injected'] is False
    assert assessment['metadata_record_count'] == 2
    assert assessment['records'][0] == {
        'direction': 'send',
        'peer_origin': '*',
        'same_origin_peer': False,
        'data_type': 'object',
        'data_keys': ['action', 'token'],
    }
    assert assessment['records'][1]['peer_origin'] == 'null'
    assert assessment['records'][1]['data_type'] == 'unknown'

    serialized = json.dumps(normalized, sort_keys=True)
    assert 'assessment-secret-value' not in serialized
    assert 'do-not-retain-message-body' not in serialized
    assert 'do-not-retain-token' not in serialized
    assert 'attacker-controlled-id' not in serialized
