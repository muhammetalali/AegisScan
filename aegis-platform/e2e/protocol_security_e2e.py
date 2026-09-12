from __future__ import annotations

import argparse
import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

import django

django.setup()

import requests
import websockets
from graphql import get_introspection_query

from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.services.stateful_protocol_security import (
    run_cross_protocol_security,
    run_graphql_security,
    run_websocket_security,
)

ALLOWED_ORIGIN = 'http://127.0.0.1:18085'
TOKENS = {
    'alice': 'alice-token',
    'expired': 'expired-token',
}


def fail(message: str) -> None:
    raise SystemExit(f'PROTOCOL_SECURITY_E2E_FAILED: {message}')


def identity() -> dict[str, Any]:
    return {
        'ref': 'alice',
        'type': 'user',
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'scopes': ['records:read'],
    }


def resource(ref: str, tenant: str, owner: str) -> dict[str, Any]:
    return {
        'ref': ref,
        'type': 'record',
        'tenant_ref': tenant,
        'owner_ref': owner,
    }


def gql_post(base: str, path: str, payload: Any, token: str = 'alice-token') -> tuple[int, Any]:
    response = requests.post(
        base + path,
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        },
        json=payload,
        timeout=5,
    )
    try:
        body = response.json()
    except ValueError:
        body = {'invalid_json': True}
    return response.status_code, body


def gql_accepted(status: int, body: Any) -> bool:
    if status >= 400:
        return False
    if isinstance(body, list):
        return bool(body) and all(
            isinstance(item, dict) and item.get('data') is not None and not item.get('errors')
            for item in body
        )
    return isinstance(body, dict) and body.get('data') is not None and not body.get('errors')


def gql_errors(body: Any) -> int:
    if isinstance(body, list):
        return sum(len(item.get('errors') or []) for item in body if isinstance(item, dict))
    if isinstance(body, dict):
        return len(body.get('errors') or [])
    return 0


def body_has_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        if key in value:
            return True
        return any(body_has_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(body_has_key(item, key) for item in value)
    return False


async def ws_connect(uri: str, *, origin: str, token: str | None, subprotocols=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    kwargs = {
        'origin': origin,
        'open_timeout': 4,
        'close_timeout': 2,
        'subprotocols': subprotocols,
    }
    try:
        return await websockets.connect(uri, additional_headers=headers, **kwargs)
    except TypeError:
        return await websockets.connect(uri, extra_headers=headers, **kwargs)


async def ws_operation(
    uri: str,
    *,
    origin: str,
    token: str | None,
    payload: Any,
    binary: bool = False,
) -> dict[str, Any]:
    try:
        ws = await ws_connect(uri, origin=origin, token=token)
    except Exception as exc:
        return {'accepted': False, 'handshake_status': 403, 'close_code': None, 'error': type(exc).__name__}
    try:
        data = payload if binary else json.dumps(payload) if not isinstance(payload, str) else payload
        await ws.send(data)
        try:
            response = await asyncio.wait_for(ws.recv(), timeout=3)
        except Exception:
            return {
                'accepted': False,
                'handshake_status': 101,
                'close_code': getattr(ws, 'close_code', None),
            }
        return {
            'accepted': True,
            'handshake_status': 101,
            'close_code': getattr(ws, 'close_code', None),
            'response_type': 'bytes' if isinstance(response, bytes) else 'text',
        }
    finally:
        await ws.close()


async def ws_rate_limited(uri: str) -> dict[str, Any]:
    ws = await ws_connect(uri, origin=ALLOWED_ORIGIN, token=TOKENS['alice'])
    try:
        for _ in range(3):
            await ws.send(json.dumps({'action': 'ping'}))
            assert json.loads(await asyncio.wait_for(ws.recv(), timeout=2))['type'] == 'pong'
        await ws.send(json.dumps({'action': 'ping'}))
        try:
            await asyncio.wait_for(ws.recv(), timeout=2)
        except Exception:
            return {'rate_limited': True, 'close_code': getattr(ws, 'close_code', None)}
        return {'rate_limited': False, 'close_code': getattr(ws, 'close_code', None)}
    finally:
        await ws.close()


async def gql_subscription(
    uri: str,
    *,
    origin: str,
    token: str | None,
    record_id: str,
    include_secret: bool,
) -> dict[str, Any]:
    document = (
        'subscription RecordChanged($id: ID!) { '
        'recordChanged(id: $id) { id tenant owner value'
        + (' secret' if include_secret else '')
        + ' } }'
    )
    try:
        ws = await ws_connect(
            uri,
            origin=origin,
            token=token,
            subprotocols=['graphql-transport-ws'],
        )
    except Exception as exc:
        return {
            'accepted': False,
            'document': document,
            'errors_count': 1,
            'sensitive_returned': [],
            'error': type(exc).__name__,
        }
    try:
        await ws.send(json.dumps({'type': 'connection_init'}))
        ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
        if ack.get('type') != 'connection_ack':
            return {'accepted': False, 'document': document, 'errors_count': 1, 'sensitive_returned': []}
        await ws.send(json.dumps({
            'id': '1',
            'type': 'subscribe',
            'payload': {
                'query': document,
                'variables': {'id': record_id},
            },
        }))
        message = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
        accepted = message.get('type') == 'next'
        rendered = json.dumps(message, sort_keys=True)
        return {
            'accepted': accepted,
            'document': document,
            'errors_count': 0 if accepted else 1,
            'sensitive_returned': ['secret'] if include_secret and 'secret' in rendered else [],
        }
    except Exception:
        return {'accepted': False, 'document': document, 'errors_count': 1, 'sensitive_returned': []}
    finally:
        await ws.close()


async def live_websocket_cases(base_ws: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    own = await ws_operation(
        f'{base_ws}/ws/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        payload={'action': 'subscribe', 'record_id': 'a1'},
    )
    fixed_cross = await ws_operation(
        f'{base_ws}/ws/tenant-b/b1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        payload={'action': 'subscribe', 'record_id': 'b1'},
    )
    fixed_origin = await ws_operation(
        f'{base_ws}/ws/tenant-a/a1',
        origin='https://evil.example',
        token=TOKENS['alice'],
        payload={'action': 'subscribe', 'record_id': 'a1'},
    )
    expired = await ws_operation(
        f'{base_ws}/ws/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['expired'],
        payload={'action': 'subscribe', 'record_id': 'a1'},
    )
    vulnerable = await ws_operation(
        f'{base_ws}/ws-vulnerable/tenant-b/b1',
        origin='https://evil.example',
        token=None,
        payload={'action': 'subscribe', 'record_id': 'b1'},
    )
    vulnerable_invalid = await ws_operation(
        f'{base_ws}/ws-vulnerable/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=None,
        payload='not-json',
    )
    fixed_invalid = await ws_operation(
        f'{base_ws}/ws/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        payload='not-json',
    )
    fixed_binary = await ws_operation(
        f'{base_ws}/ws/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        payload=b'fixture-binary',
        binary=True,
    )
    oversized_payload = {
        'action': 'subscribe',
        'record_id': 'a1',
        'padding': 'x' * 2048,
    }
    fixed_oversized = await ws_operation(
        f'{base_ws}/ws/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        payload=oversized_payload,
    )
    rate = await ws_rate_limited(f'{base_ws}/ws/tenant-a/a1')
    reconnect_first = await ws_operation(
        f'{base_ws}/ws-vulnerable/tenant-b/b1',
        origin='https://evil.example',
        token=None,
        payload={'action': 'ping'},
    )
    reconnect_second = await ws_operation(
        f'{base_ws}/ws-vulnerable/tenant-b/b1',
        origin='https://evil.example',
        token=None,
        payload={'action': 'ping'},
    )

    cases = [
        {
            'ref': 'ws-fixed-own',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'subscribe',
            'expected_allowed': True,
            'server_accepted': own['accepted'],
            'handshake_status': own['handshake_status'],
            'subscription_owner_ref': 'alice',
            'subscription_tenant_ref': 'tenant-a',
            'message_schema_valid': True,
            'message_authorized': True,
        },
        {
            'ref': 'ws-fixed-cross-tenant',
            'identity': identity(),
            'resource': resource('b1', 'tenant-b', 'bob'),
            'channel': f'{base_ws}/ws/tenant-b/b1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'subscribe',
            'expected_allowed': False,
            'server_accepted': fixed_cross['accepted'],
            'handshake_status': fixed_cross['handshake_status'],
            'subscription_owner_ref': 'bob',
            'subscription_tenant_ref': 'tenant-b',
            'message_schema_valid': True,
            'message_authorized': False,
        },
        {
            'ref': 'ws-fixed-origin-denied',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': 'https://evil.example',
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'subscribe',
            'expected_allowed': False,
            'server_accepted': fixed_origin['accepted'],
            'handshake_status': fixed_origin['handshake_status'],
        },
        {
            'ref': 'ws-fixed-expired-session',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'expired',
            'requested_action': 'subscribe',
            'expected_allowed': False,
            'server_accepted': expired['accepted'],
            'handshake_status': expired['handshake_status'],
        },
        {
            'ref': 'ws-vulnerable-cross-origin-tenant',
            'identity': identity(),
            'resource': resource('b1', 'tenant-b', 'bob'),
            'channel': f'{base_ws}/ws-vulnerable/tenant-b/b1',
            'origin': 'https://evil.example',
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': False,
            'session_state': 'unknown',
            'requested_action': 'subscribe',
            'expected_allowed': False,
            'server_accepted': vulnerable['accepted'],
            'handshake_status': vulnerable['handshake_status'],
            'subscription_owner_ref': 'bob',
            'subscription_tenant_ref': 'tenant-b',
            'message_schema_valid': True,
            'message_authorized': False,
        },
        {
            'ref': 'ws-fixed-invalid-schema',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'message',
            'expected_allowed': False,
            'server_accepted': fixed_invalid['accepted'],
            'handshake_status': fixed_invalid['handshake_status'],
            'message_schema_valid': False,
            'message_authorized': True,
        },
        {
            'ref': 'ws-vulnerable-invalid-schema',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws-vulnerable/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': False,
            'session_state': 'unknown',
            'requested_action': 'message',
            'expected_allowed': False,
            'server_accepted': vulnerable_invalid['accepted'],
            'handshake_status': vulnerable_invalid['handshake_status'],
            'message_schema_valid': False,
            'message_authorized': False,
        },
        {
            'ref': 'ws-fixed-binary',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'binary',
            'expected_allowed': False,
            'server_accepted': fixed_binary['accepted'],
            'handshake_status': fixed_binary['handshake_status'],
            'binary': True,
            'binary_allowed': False,
        },
        {
            'ref': 'ws-fixed-oversized',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'subscribe',
            'expected_allowed': False,
            'server_accepted': fixed_oversized['accepted'],
            'handshake_status': fixed_oversized['handshake_status'],
            'message_size_bytes': len(json.dumps(oversized_payload).encode()),
            'max_message_size_bytes': 1024,
        },
        {
            'ref': 'ws-fixed-rate-limit',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'channel': f'{base_ws}/ws/tenant-a/a1',
            'origin': ALLOWED_ORIGIN,
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': True,
            'session_state': 'active',
            'requested_action': 'rate',
            'expected_allowed': False,
            'server_accepted': False,
            'handshake_status': 101,
            'observed_messages': 4,
            'rate_limit_threshold': 3,
            'rate_limited': rate['rate_limited'],
        },
        {
            'ref': 'ws-vulnerable-reconnect-no-reauth',
            'identity': identity(),
            'resource': resource('b1', 'tenant-b', 'bob'),
            'channel': f'{base_ws}/ws-vulnerable/tenant-b/b1',
            'origin': 'https://evil.example',
            'allowed_origins': [ALLOWED_ORIGIN],
            'authentication_required': True,
            'authenticated': False,
            'session_state': 'unknown',
            'requested_action': 'reconnect',
            'expected_allowed': False,
            'server_accepted': reconnect_first['accepted'] and reconnect_second['accepted'],
            'handshake_status': 101,
            'subscription_tenant_ref': 'tenant-b',
            'reconnect': True,
            'reconnect_reauthenticated': False,
        },
    ]
    return cases, {
        'fixed_own': own['accepted'],
        'fixed_cross': fixed_cross['accepted'],
        'vulnerable_cross': vulnerable['accepted'],
        'rate_limited': rate['rate_limited'],
    }


async def live_graphql_subscription_cases(base_ws: str) -> list[dict[str, Any]]:
    own = await gql_subscription(
        f'{base_ws}/graphql-ws/tenant-a/a1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        record_id='a1',
        include_secret=False,
    )
    fixed_cross = await gql_subscription(
        f'{base_ws}/graphql-ws/tenant-b/b1',
        origin=ALLOWED_ORIGIN,
        token=TOKENS['alice'],
        record_id='b1',
        include_secret=False,
    )
    vulnerable_cross = await gql_subscription(
        f'{base_ws}/graphql-ws-vulnerable/tenant-b/b1',
        origin='https://evil.example',
        token=None,
        record_id='b1',
        include_secret=True,
    )
    return [
        {
            'ref': 'gql-subscription-own',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'endpoint': f'{base_ws}/graphql-ws/tenant-a/a1',
            'operation_type': 'subscription',
            'operation_name': 'RecordChanged',
            'document': own['document'],
            'field_path': 'recordChanged',
            'expected_allowed': True,
            'server_accepted': own['accepted'],
            'response_status': 101,
            'errors_count': own['errors_count'],
            'field_authorized': True,
            'subscription_owner_ref': 'alice',
            'subscription_tenant_ref': 'tenant-a',
            'sensitive_fields_requested': [],
            'sensitive_fields_returned': [],
            'depth': 1,
            'complexity': 1,
        },
        {
            'ref': 'gql-subscription-fixed-cross',
            'identity': identity(),
            'resource': resource('b1', 'tenant-b', 'bob'),
            'endpoint': f'{base_ws}/graphql-ws/tenant-b/b1',
            'operation_type': 'subscription',
            'operation_name': 'RecordChanged',
            'document': fixed_cross['document'],
            'field_path': 'recordChanged',
            'expected_allowed': False,
            'server_accepted': fixed_cross['accepted'],
            'response_status': 403,
            'errors_count': fixed_cross['errors_count'],
            'field_authorized': False,
            'subscription_owner_ref': 'bob',
            'subscription_tenant_ref': 'tenant-b',
        },
        {
            'ref': 'gql-subscription-vulnerable-cross',
            'identity': identity(),
            'resource': resource('b1', 'tenant-b', 'bob'),
            'endpoint': f'{base_ws}/graphql-ws-vulnerable/tenant-b/b1',
            'operation_type': 'subscription',
            'operation_name': 'RecordChanged',
            'document': vulnerable_cross['document'],
            'field_path': 'recordChanged.secret',
            'expected_allowed': False,
            'server_accepted': vulnerable_cross['accepted'],
            'response_status': 101,
            'errors_count': vulnerable_cross['errors_count'],
            'field_authorized': False,
            'subscription_owner_ref': 'bob',
            'subscription_tenant_ref': 'tenant-b',
            'sensitive_fields_requested': ['secret'],
            'sensitive_fields_returned': vulnerable_cross['sensitive_returned'],
        },
    ]


def live_graphql_http_cases(base_http: str) -> list[dict[str, Any]]:
    own_query = 'query Record($id: ID!) { record(id: $id) { id tenant owner value } }'
    secret_query = 'query Secret($id: ID!) { record(id: $id) { id secret } }'
    introspection = get_introspection_query(descriptions=False)
    mutation = 'mutation UpdateRecord($id: ID!, $value: String!) { updateRecord(id: $id, value: $value) { id value } }'
    deep = 'query Deep($id: ID!) { record(id: $id) { related { related { related { related { related { id } } } } } } }'
    aliases = ' '.join(f'f{i}: id' for i in range(30))
    complex_query = f'query Complex($id: ID!) {{ record(id: $id) {{ {aliases} }} }}'

    def execute(ref: str, path: str, query: str, variables: dict[str, Any], expected: bool, resource_value: dict[str, Any], **extra):
        status, body = gql_post(base_http, path, {
            'query': query,
            'operationName': ref,
            'variables': variables,
        })
        return status, body, {
            'ref': extra.pop('case_ref', ref),
            'identity': identity(),
            'resource': resource_value,
            'endpoint': path,
            'operation_type': extra.pop('operation_type', 'query'),
            'operation_name': ref,
            'document': query,
            'field_path': extra.pop('field_path', ''),
            'expected_allowed': expected,
            'server_accepted': gql_accepted(status, body),
            'response_status': status,
            'errors_count': gql_errors(body),
            **extra,
        }

    cases: list[dict[str, Any]] = []
    _, _, own = execute(
        'Record', '/graphql', own_query, {'id': 'a1'}, True,
        resource('a1', 'tenant-a', 'alice'),
        field_path='record.value',
    )
    cases.append(own)

    _, _, fixed_cross = execute(
        'Record', '/graphql', own_query, {'id': 'b1'}, False,
        resource('b1', 'tenant-b', 'bob'),
        case_ref='gql-fixed-cross',
        field_path='record.value',
        field_authorized=False,
    )
    cases.append(fixed_cross)

    _, _, vulnerable_cross = execute(
        'Record', '/graphql-vulnerable', own_query, {'id': 'b1'}, False,
        resource('b1', 'tenant-b', 'bob'),
        case_ref='gql-vulnerable-cross',
        field_path='record.value',
        field_authorized=False,
    )
    cases.append(vulnerable_cross)

    _, fixed_secret_body, fixed_secret = execute(
        'Secret', '/graphql', secret_query, {'id': 'a1'}, False,
        resource('a1', 'tenant-a', 'alice'),
        case_ref='gql-fixed-secret',
        field_path='record.secret',
        field_authorized=False,
        sensitive_fields_requested=['secret'],
        sensitive_fields_returned=[],
    )
    if body_has_key(fixed_secret_body, 'secret'):
        fail('fixed GraphQL sensitive-field path returned secret data')
    fixed_secret['sensitive_fields_returned'] = []
    cases.append(fixed_secret)

    _, vulnerable_secret_body, vulnerable_secret = execute(
        'Secret', '/graphql-vulnerable', secret_query, {'id': 'a1'}, False,
        resource('a1', 'tenant-a', 'alice'),
        case_ref='gql-vulnerable-secret',
        field_path='record.secret',
        field_authorized=False,
        sensitive_fields_requested=['secret'],
        sensitive_fields_returned=[],
    )
    vulnerable_returned_secret = body_has_key(vulnerable_secret_body, 'secret')
    if not vulnerable_returned_secret:
        fail('vulnerable GraphQL sensitive-field fixture did not expose secret field')
    vulnerable_secret['sensitive_fields_returned'] = ['secret']
    cases.append(vulnerable_secret)

    for path, case_ref, expected in [
        ('/graphql', 'gql-fixed-introspection', False),
        ('/graphql-vulnerable', 'gql-vulnerable-introspection', False),
    ]:
        status, body = gql_post(base_http, path, {
            'query': introspection,
            'operationName': 'IntrospectionQuery',
        })
        schema_introspection = (
            body
            if isinstance(body, dict)
            and isinstance(body.get('data'), dict)
            and isinstance(body['data'].get('__schema'), dict)
            else None
        )
        cases.append({
            'ref': case_ref,
            'identity': identity(),
            'resource': resource('schema', 'tenant-a', 'alice'),
            'endpoint': path,
            'operation_type': 'query',
            'operation_name': 'IntrospectionQuery',
            'document': introspection,
            'schema_introspection': schema_introspection,
            'field_path': '__schema',
            'expected_allowed': expected,
            'server_accepted': gql_accepted(status, body),
            'response_status': status,
            'errors_count': gql_errors(body),
            'introspection_requested': True,
            'introspection_expected_allowed': False,
        })

    for path, case_ref in [
        ('/graphql', 'gql-fixed-mutation'),
        ('/graphql-vulnerable', 'gql-vulnerable-mutation'),
    ]:
        status, body = gql_post(base_http, path, {
            'query': mutation,
            'operationName': 'UpdateRecord',
            'variables': {'id': 'a1', 'value': 'updated'},
        })
        cases.append({
            'ref': case_ref,
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'endpoint': path,
            'operation_type': 'mutation',
            'operation_name': 'UpdateRecord',
            'document': mutation,
            'field_path': 'updateRecord',
            'expected_allowed': False,
            'server_accepted': gql_accepted(status, body),
            'response_status': status,
            'errors_count': gql_errors(body),
            'mutation_authorized': False,
        })

    batch_payload = [
        {'query': own_query, 'operationName': 'Record', 'variables': {'id': 'a1'}},
        {'query': own_query, 'operationName': 'Record', 'variables': {'id': 'a1'}},
    ]
    for path, case_ref in [
        ('/graphql', 'gql-fixed-batch'),
        ('/graphql-vulnerable', 'gql-vulnerable-batch'),
    ]:
        status, body = gql_post(base_http, path, batch_payload)
        cases.append({
            'ref': case_ref,
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'endpoint': path,
            'operation_type': 'query',
            'operation_name': 'Record',
            'document': own_query,
            'field_path': 'record',
            'expected_allowed': False,
            'server_accepted': gql_accepted(status, body),
            'response_status': status,
            'errors_count': gql_errors(body),
            'batch_size': 2,
            'max_batch_size': 1,
        })

    for query, label, max_depth, max_complexity in [
        (deep, 'depth', 4, 100),
        (complex_query, 'complexity', 8, 25),
    ]:
        for path, prefix in [
            ('/graphql', 'fixed'),
            ('/graphql-vulnerable', 'vulnerable'),
        ]:
            status, body = gql_post(base_http, path, {
                'query': query,
                'operationName': 'Deep' if label == 'depth' else 'Complex',
                'variables': {'id': 'a1'},
            })
            cases.append({
                'ref': f'gql-{prefix}-{label}',
                'identity': identity(),
                'resource': resource('a1', 'tenant-a', 'alice'),
                'endpoint': path,
                'operation_type': 'query',
                'operation_name': 'Deep' if label == 'depth' else 'Complex',
                'document': query,
                'field_path': 'record',
                'expected_allowed': False,
                'server_accepted': gql_accepted(status, body),
                'response_status': status,
                'errors_count': gql_errors(body),
                'max_depth': max_depth,
                'max_complexity': max_complexity,
            })

    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--http-origin', default='http://127.0.0.1:18085')
    parser.add_argument('--ws-origin', default='ws://127.0.0.1:18085')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()

    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f'protocol-e2e-{suffix}@example.com',
        password='Protocol-E2E-Only-Password!42',
        first_name='Protocol',
        last_name='E2E',
    )
    project = Project.objects.create(
        name=f'Protocol Security E2E {suffix}',
        slug=f'protocol-security-e2e-{suffix}',
        owner=user,
        environment=Project.Environment.STAGING,
    )

    ws_cases, ws_live = asyncio.run(live_websocket_cases(args.ws_origin))
    gql_cases = live_graphql_http_cases(args.http_origin)
    gql_cases.extend(asyncio.run(live_graphql_subscription_cases(args.ws_origin)))
    for case in [*ws_cases, *gql_cases]:
        case.setdefault('session_ref', 'alice-session')

    ws_run, ws_observations = run_websocket_security(project, str(user.id), ws_cases)
    gql_run, gql_observations = run_graphql_security(project, str(user.id), gql_cases)

    ws_by_ref = {item.case_ref: item for item in ws_observations}
    gql_by_ref = {item.case_ref: item for item in gql_observations}

    if not ws_by_ref['ws-fixed-own'].passed:
        fail('fixed own WebSocket validation did not pass')
    if not ws_by_ref['ws-fixed-cross-tenant'].passed:
        fail('fixed cross-tenant WebSocket denial did not pass')
    if ws_by_ref['ws-vulnerable-cross-origin-tenant'].passed:
        fail('vulnerable WebSocket cross-origin/cross-tenant case was not detected')
    if ws_by_ref['ws-vulnerable-invalid-schema'].passed:
        fail('vulnerable WebSocket schema acceptance was not detected')
    if ws_by_ref['ws-vulnerable-reconnect-no-reauth'].passed:
        fail('WebSocket reconnect without reauthentication was not detected')
    if not ws_live['rate_limited']:
        fail('fixed WebSocket rate limiting was not observed live')

    required_graphql_failures = {
        'gql-vulnerable-cross',
        'gql-vulnerable-secret',
        'gql-vulnerable-introspection',
        'gql-vulnerable-mutation',
        'gql-vulnerable-batch',
        'gql-vulnerable-depth',
        'gql-vulnerable-complexity',
        'gql-subscription-vulnerable-cross',
    }
    required_graphql_passes = {
        'Record',
        'gql-fixed-cross',
        'gql-fixed-secret',
        'gql-fixed-introspection',
        'gql-fixed-mutation',
        'gql-fixed-batch',
        'gql-fixed-depth',
        'gql-fixed-complexity',
        'gql-subscription-own',
        'gql-subscription-fixed-cross',
    }
    for ref in required_graphql_failures:
        if gql_by_ref[ref].passed:
            fail(f'vulnerable GraphQL case was not detected: {ref}')
    for ref in required_graphql_passes:
        if not gql_by_ref[ref].passed:
            fail(f'fixed GraphQL case did not pass: {ref}: {gql_by_ref[ref].reason}')

    cross_cases = [
        {
            'ref': 'fixed-gql-to-ws',
            'identity': identity(),
            'resource': resource('a1', 'tenant-a', 'alice'),
            'session_ref': 'alice-session',
            'from_protocol': 'graphql',
            'to_protocol': 'websocket',
            'operation': 'subscribe',
            'expected_allowed': False,
            'observed_allowed': False,
            'identity_consistent': False,
            'tenant_consistent': False,
            'session_bound': False,
            'source_observation_id': str(gql_by_ref['Record'].id),
            'target_observation_id': str(ws_by_ref['ws-fixed-own'].id),
        },
        {
            'ref': 'vulnerable-cross-protocol-chain',
            'identity': identity(),
            'resource': resource('b1', 'tenant-b', 'bob'),
            'session_ref': 'alice-session',
            'from_protocol': 'graphql',
            'to_protocol': 'websocket',
            'operation': 'subscribe',
            'expected_allowed': True,
            'observed_allowed': False,
            'identity_consistent': True,
            'tenant_consistent': True,
            'session_bound': False,
            'source_observation_id': str(gql_by_ref['gql-vulnerable-cross'].id),
            'target_observation_id': str(ws_by_ref['ws-vulnerable-cross-origin-tenant'].id),
        },
    ]
    cross_run, cross_observations = run_cross_protocol_security(
        project,
        str(user.id),
        cross_cases,
    )
    cross_by_ref = {item.case_ref: item for item in cross_observations}
    if not cross_by_ref['fixed-gql-to-ws'].passed:
        fail('fixed cross-protocol transition did not pass')
    if cross_by_ref['vulnerable-cross-protocol-chain'].passed:
        fail('vulnerable cross-protocol chain was not detected')

    graph_kinds = set(project.security_graph_nodes.values_list('kind', flat=True))
    required_graph_kinds = {
        'identity', 'resource', 'websocket_channel', 'graphql_operation',
        'graphql_type', 'graphql_field', 'graphql_argument', 'session', 'channel',
    }
    if not required_graph_kinds.issubset(graph_kinds):
        fail(f'protocol graph kinds missing: {sorted(graph_kinds)}')

    evidence = {
        'schema': 'aegis.protocol-security-e2e.v1',
        'status': 'success',
        'project_id': str(project.id),
        'runs': {
            'websocket': {'id': str(ws_run.id), 'summary': ws_run.summary},
            'graphql': {'id': str(gql_run.id), 'summary': gql_run.summary},
            'cross_protocol': {'id': str(cross_run.id), 'summary': cross_run.summary},
        },
        'failed_case_refs': sorted([
            item.case_ref
            for item in [*ws_observations, *gql_observations, *cross_observations]
            if not item.passed
        ]),
        'evidence_fingerprints': sorted({
            item.evidence_fingerprint
            for item in [*ws_observations, *gql_observations, *cross_observations]
            if item.evidence_fingerprint
        }),
        'graph_kinds': sorted(graph_kinds),
        'graph_relations': sorted(set(project.security_graph_edges.values_list('relation', flat=True))),
        'live_assertions': ws_live,
    }
    rendered = json.dumps(evidence, sort_keys=True, indent=2)
    for secret in TOKENS.values():
        if secret in rendered:
            fail('credential material leaked into protocol evidence artifact')
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(rendered + '\n', encoding='utf-8')
    print(rendered)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
