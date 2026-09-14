#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


FORBIDDEN_SECRET_VALUES = (
    'browser-fixture-token',
    'browser-query-secret',
    'acct-secret-42',
    'graphql-secret-value-never-persist',
    'client-cookie-secret-must-not-persist',
    'server-cookie-secret-must-not-persist',
    'storage-secret-must-not-persist',
    'session-secret-must-not-persist',
    'dark-secret-value-never-persist',
    'tenant-a-secret-never-persist',
    'response-secret-must-not-persist',
)

_WEB_MESSAGING_RECORD_KEYS = {
    'direction',
    'peer_origin',
    'same_origin_peer',
    'data_type',
    'data_keys',
}


def _fail(message: str) -> None:
    raise AssertionError(message)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit('usage: browser_spa_discovery_e2e.py <artifact.json>')
    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding='utf-8'))
    rendered = json.dumps(data, sort_keys=True)

    if data.get('schema') != 'aegis.browser-spa-discovery.v1':
        _fail('unexpected browser SPA evidence schema')
    if data.get('identity_ref') != 'alice':
        _fail('identity isolation reference was not preserved')

    for secret in FORBIDDEN_SECRET_VALUES:
        if secret in rendered:
            _fail(f'secret material leaked into evidence: {secret}')

    observations = data.get('observations')
    if not isinstance(observations, list) or not observations:
        _fail('browser SPA discovery produced no observations')

    summaries = [item for item in observations if item.get('kind') == 'browser-spa-summary']
    if len(summaries) != 1:
        _fail('browser SPA summary is missing or duplicated')
    summary = summaries[0]

    if summary.get('profile_isolation') != 'dedicated-ephemeral-user-data-dir':
        _fail('browser profile isolation was not proven')
    if summary.get('credential_transport') != 'same-origin-request-interception':
        _fail('same-origin credential transport was not proven')
    if summary.get('network_isolation') != 'scope-validated-socks5-plus-cdp':
        _fail('scope-validating browser network boundary was not proven')
    if int(summary.get('proxy_blocked_connection_count') or 0) < 1:
        _fail('worker-context out-of-scope egress did not reach the scope proxy block')
    if int(summary.get('proxy_allowed_connection_count') or 0) < 1:
        _fail('scope proxy did not prove any authorized browser connection')
    if int(summary.get('blocked_out_of_scope_request_count') or 0) < 1:
        _fail('out-of-scope browser egress was not blocked')
    if int(summary.get('blocked_websocket_count') or 0) < 1:
        _fail('cross-origin WebSocket creation was not blocked before page script execution')
    if int(summary.get('post_message_listener_count') or 0) < 1:
        _fail('postMessage runtime listener discovery was not proven')
    if int(summary.get('inner_html_write_count') or 0) < 1:
        _fail('DOM sink instrumentation was not exercised')

    web_messaging = [
        item for item in observations
        if item.get('kind') == 'browser-web-messaging-assessment'
    ]
    if len(web_messaging) != 1:
        _fail('WSTG-CLNT-11 browser web-messaging assessment is missing or duplicated')
    web_message = web_messaging[0]
    if web_message.get('wstg_id') != 'WSTG-CLNT-11':
        _fail(f'unexpected web-messaging methodology binding: {web_message.get("wstg_id")}')
    if web_message.get('status') != 'observed':
        _fail(f'fixture postMessage activity was not observed: {web_message.get("status")}')
    if web_message.get('observation_only') is not True or web_message.get('final_decision') is not False:
        _fail('web-messaging evidence crossed the observation-only decision boundary')
    if web_message.get('origin_validation_confirmed') is not False:
        _fail('passive telemetry incorrectly claimed receiver origin validation')
    if web_message.get('payload_values_captured') is not False:
        _fail('web-messaging assessment claimed payload-value capture')
    if web_message.get('synthetic_cross_origin_messages_injected') is not False:
        _fail('browser capability unexpectedly claimed active cross-origin message injection')
    if int(web_message.get('listener_count') or 0) < 1:
        _fail('web-messaging assessment did not preserve listener evidence')
    if int(web_message.get('send_count') or 0) < 1:
        _fail('web-messaging assessment did not preserve send evidence')
    if int(web_message.get('metadata_record_count') or 0) < 1:
        _fail('web-messaging assessment produced no bounded metadata records')
    if int(web_message.get('wildcard_target_count') or 0) < 1 or web_message.get('wildcard_target_observed') is not True:
        _fail('fixture wildcard postMessage target was not observed')

    message_records = web_message.get('records')
    if not isinstance(message_records, list) or not message_records:
        _fail('web-messaging assessment records are missing')
    for record in message_records:
        if not isinstance(record, dict):
            _fail('web-messaging assessment record is not an object')
        unexpected = set(record) - _WEB_MESSAGING_RECORD_KEYS
        if unexpected:
            _fail(f'web-messaging record leaked unapproved fields: {sorted(unexpected)}')
    wildcard_fixture_sends = [
        record for record in message_records
        if record.get('direction') == 'send'
        and record.get('peer_origin') == '*'
        and record.get('data_type') == 'object'
        and record.get('data_keys') == ['type']
    ]
    if not wildcard_fixture_sends:
        _fail('metadata-only fixture postMessage record was not proven')

    local_keys = set(summary.get('local_storage_keys') or [])
    session_keys = set(summary.get('session_storage_keys') or [])
    if not {'access_token', 'theme'} <= local_keys:
        _fail(f'expected localStorage key inventory missing: {local_keys}')
    if not {'bootstrap', 'workspace'} <= session_keys:
        _fail(f'expected sessionStorage key inventory missing: {session_keys}')

    cookie_names = {item.get('name') for item in summary.get('cookies') or [] if isinstance(item, dict)}
    if not {'client_session', 'server_session'} <= cookie_names:
        _fail(f'expected cookie metadata missing: {cookie_names}')
    if any('value' in item for item in summary.get('cookies') or [] if isinstance(item, dict)):
        _fail('cookie value leaked into browser evidence')

    routes = {item.get('url') for item in observations if item.get('kind') == 'browser-page-route'}
    if 'http://127.0.0.1:18083/dashboard' not in routes:
        _fail('SPA route discovery did not capture dashboard')

    endpoints = {
        (item.get('method'), item.get('url')): item
        for item in observations
        if item.get('kind') == 'browser-http-endpoint'
    }
    profile = endpoints.get(('GET', 'http://127.0.0.1:18083/api/profile?token=*&view=*'))
    if not profile or profile.get('status') != 200:
        _fail(f'same-origin authenticated runtime API was not proven: {profile}')
    graphql_http = endpoints.get(('POST', 'http://127.0.0.1:18083/graphql'))
    if not graphql_http or graphql_http.get('status') != 200:
        _fail(f'authenticated GraphQL HTTP request was not proven: {graphql_http}')
    third_party = endpoints.get(('GET', 'http://127.0.0.1:18084/third-party'))
    if not third_party or third_party.get('status') != 204:
        _fail(f'cross-origin credential isolation failed: {third_party}')

    graphql_ops = [
        item for item in observations
        if item.get('kind') == 'browser-graphql-operation'
        and item.get('operation_name') == 'Viewer'
    ]
    if len(graphql_ops) != 1:
        _fail('GraphQL operation discovery did not capture Viewer')
    if set(graphql_ops[0].get('variable_keys') or []) != {'accountId', 'secretToken'}:
        _fail('GraphQL variable-name discovery is incomplete')

    ws_urls = {
        item.get('url')
        for item in observations
        if item.get('kind') == 'browser-websocket-channel'
    }
    if 'ws://127.0.0.1:18083/ws' not in ws_urls:
        _fail(f'WebSocket channel was not discovered: {ws_urls}')

    scripts = [
        item for item in observations
        if item.get('kind') == 'browser-javascript-resource'
        and item.get('url') == 'http://127.0.0.1:18083/static/app.js'
    ]
    if len(scripts) != 1:
        _fail('runtime JavaScript resource was not discovered')
    if scripts[0].get('source_map_url') != 'http://127.0.0.1:18083/static/app.js.map':
        _fail(f'source-map discovery failed: {scripts[0]}')

    print(json.dumps({
        'schema': 'aegis.browser-spa-discovery-e2e-proof.v1',
        'passed': True,
        'observation_count': len(observations),
        'route_count': len(routes),
        'endpoint_count': len(endpoints),
        'graphql_operation_count': len(graphql_ops),
        'websocket_count': len(ws_urls),
        'web_messaging_listener_count': int(web_message.get('listener_count') or 0),
        'web_messaging_send_count': int(web_message.get('send_count') or 0),
        'web_messaging_receive_count': int(web_message.get('receive_count') or 0),
        'web_messaging_metadata_record_count': int(web_message.get('metadata_record_count') or 0),
        'web_messaging_wildcard_target_count': int(web_message.get('wildcard_target_count') or 0),
        'blocked_out_of_scope_requests': int(summary.get('blocked_out_of_scope_request_count') or 0),
        'blocked_cross_origin_websockets': int(summary.get('blocked_websocket_count') or 0),
        'blocked_cross_origin_webtransports': int(summary.get('blocked_webtransport_count') or 0),
        'proxy_blocked_connections': int(summary.get('proxy_blocked_connection_count') or 0),
        'proxy_allowed_connections': int(summary.get('proxy_allowed_connection_count') or 0),
        'secret_leakage': False,
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
