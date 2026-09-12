from __future__ import annotations

import asyncio
import json
import os
import stat
from types import SimpleNamespace

import pytest

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from django_project.users.models import User, UserRole
from enterprise.web_security_models import SecurityGraphEdge, SecurityGraphNode
from fastapi_app.services.browser_spa_discovery import (
    _ScopedSocksProxy,
    _canonical_url,
    _graphql_metadata,
    _load_session,
    _origin,
)
from fastapi_app.services.browser_surface_graph import project_browser_surface_graph
from fastapi_app.services.credential_execution import (
    assert_no_credential_material_leaked,
    authorize_credential_refs_for_execution,
    resolve_credential_refs_for_worker,
)
from fastapi_app.services.native_output_normalizer import normalize_native_output
from fastapi_app.services.native_tool_runtime import _browser_session_file

CI_FERNET_KEY = 'Gda3DhfD-EcoacpdQeTFnHHH1Q_rxQZaUISBiMvSwUM='


@pytest.fixture(autouse=True)
def configured_vault(settings):
    settings.CREDENTIAL_VAULT_KEYS = CI_FERNET_KEY
    settings.CREDENTIAL_FINGERPRINT_KEY = 'browser-ci-fingerprint-key'


@pytest.fixture
def actor():
    return User.objects.create_user(
        email='browser-owner@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Browser',
        last_name='Owner',
        role=UserRole.ADMIN,
    )


@pytest.fixture
def project(actor):
    return Project.objects.create(
        name='Browser Security',
        slug='browser-security',
        owner=actor,
        environment=Project.Environment.STAGING,
    )


def test_browser_url_and_graphql_metadata_redact_values():
    assert _origin('ws://app.example.test/socket') == 'http://app.example.test'
    assert _origin('wss://app.example.test/socket') == 'https://app.example.test'
    canonical = _canonical_url(
        'https://app.example.test/api/items?token=secret-value&id=42&id=43#fragment'
    )
    assert canonical == 'https://app.example.test/api/items?id=*&token=*'
    assert 'secret-value' not in canonical
    assert '42' not in canonical

    metadata = _graphql_metadata(json.dumps({
        'operationName': 'AccountSummary',
        'query': 'query AccountSummary($secretToken: String!, $accountId: ID!) { account(id: $accountId) { id } }',
        'variables': {'secretToken': 'do-not-persist', 'accountId': 'acct-42'},
    }))
    assert metadata == {
        'operation_type': 'query',
        'operation_name': 'AccountSummary',
        'variable_keys': ['accountId', 'secretToken'],
    }
    assert 'do-not-persist' not in str(metadata)
    assert 'acct-42' not in str(metadata)


@pytest.mark.asyncio
async def test_scoped_socks_proxy_relays_only_authorized_targets(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1')
    monkeypatch.setenv('ALLOW_SINGLE_LABEL_SCAN_TARGETS', '0')

    async def echo(reader, writer):
        try:
            payload = await reader.readexactly(4)
            writer.write(payload)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    upstream = await asyncio.start_server(echo, '127.0.0.1', 0)
    upstream_port = int(upstream.sockets[0].getsockname()[1])
    proxy = _ScopedSocksProxy()
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', proxy.port)
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        assert await reader.readexactly(2) == b'\x05\x00'
        writer.write(
            b'\x05\x01\x00\x01'
            + bytes((127, 0, 0, 1))
            + upstream_port.to_bytes(2, 'big')
        )
        await writer.drain()
        allowed_reply = await reader.readexactly(10)
        assert allowed_reply[1] == 0
        writer.write(b'ping')
        await writer.drain()
        assert await reader.readexactly(4) == b'ping'
        writer.close()
        await writer.wait_closed()

        blocked_reader, blocked_writer = await asyncio.open_connection('127.0.0.1', proxy.port)
        blocked_writer.write(b'\x05\x01\x00')
        await blocked_writer.drain()
        assert await blocked_reader.readexactly(2) == b'\x05\x00'
        blocked_writer.write(
            b'\x05\x01\x00\x01'
            + bytes((198, 51, 100, 1))
            + (80).to_bytes(2, 'big')
        )
        await blocked_writer.drain()
        blocked_reply = await blocked_reader.readexactly(10)
        assert blocked_reply[1] == 2
        blocked_writer.close()
        await blocked_writer.wait_closed()

        assert proxy.allowed_connections == 1
        assert proxy.blocked_connections == 1
    finally:
        await proxy.close()
        upstream.close()
        await upstream.wait_closed()


def test_browser_session_file_is_0600_and_contract_bounded(tmp_path):
    secret = json.dumps({
        'headers': {'Authorization': 'Bearer super-secret-browser-token'},
        'cookies': [{'name': 'session', 'value': 'super-secret-cookie', 'path': '/'}],
        'local_storage': {'access_token': 'super-secret-storage'},
        'session_storage': {'workspace': 'tenant-a'},
    })
    path = _browser_session_file(secret)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600
        loaded = _load_session(path)
        assert loaded['headers']['Authorization'].startswith('Bearer ')
        assert loaded['cookies'][0]['name'] == 'session'
    finally:
        os.unlink(path)


@pytest.mark.django_db
def test_browser_session_credential_requires_exact_origin_scope(project, actor):
    secret = json.dumps({
        'headers': {'Authorization': 'Bearer browser-session-secret'},
        'local_storage': {'access_token': 'browser-storage-secret'},
    })
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='browser-session',
        kind=CredentialSecret.Kind.GENERIC,
        secret=secret,
        scope={'browser_origin': 'https://app.example.test', 'browser_identity_ref': 'alice'},
    )

    context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=actor.id,
        refs=[str(credential.id)],
        capability_id='browser.spa-discovery',
        allowed_kinds=('generic',),
        purpose='browser-test:authorize',
        target='https://app.example.test/account/profile',
    )
    assert context['credential_material_handling'] == 'reference-authorized-only'
    assert context['credential_refs'][0]['credential_ref'] == str(credential.id)
    assert context['credential_refs'][0]['browser_identity_ref'] == 'alice'
    assert 'browser-session-secret' not in str(context)

    materials, worker_context = resolve_credential_refs_for_worker(
        project_id=project.id,
        actor_id=actor.id,
        refs=[str(credential.id)],
        capability_id='browser.spa-discovery',
        allowed_kinds=('generic',),
        purpose='browser-test:worker-resolve',
        target='https://app.example.test/account/profile',
    )
    assert materials[0]['secret'] == secret
    assert worker_context['credential_refs'][0]['credential_ref'] == str(credential.id)
    assert worker_context['credential_refs'][0]['browser_identity_ref'] == 'alice'
    assert materials[0]['browser_identity_ref'] == 'alice'
    assert 'browser-session-secret' not in str(worker_context)

    with pytest.raises(CredentialVaultDenied):
        authorize_credential_refs_for_execution(
            project_id=project.id,
            actor_id=actor.id,
            refs=[str(credential.id)],
            capability_id='browser.spa-discovery',
            allowed_kinds=('generic',),
            purpose='browser-test:cross-origin',
            target='https://other.example.test/account/profile',
        )

    denied = CredentialAccess.objects.filter(
        credential=credential,
        result=CredentialAccess.Result.DENIED,
    ).latest('created_at')
    assert denied.metadata['scope_type'] == 'browser_origin'
    assert denied.metadata['scope_matches_target'] is False
    assert 'browser-session-secret' not in str(denied.metadata)


@pytest.mark.django_db
def test_browser_identity_binding_falls_back_to_credential_reference(project, actor):
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='browser-session-fallback',
        kind=CredentialSecret.Kind.GENERIC,
        secret=json.dumps({'headers': {'Authorization': 'Bearer fallback-token'}}),
        scope={'browser_origin': 'https://app.example.test'},
    )

    context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=actor.id,
        refs=[str(credential.id)],
        capability_id='browser.spa-discovery',
        allowed_kinds=('generic',),
        target='https://app.example.test/',
    )

    assert context['credential_refs'][0]['browser_identity_ref'] == f'credential:{credential.id}'


def test_browser_session_nested_secret_values_are_rejected_from_payloads():
    session_secret = json.dumps({
        'headers': {
            'Authorization': 'Bearer nested-browser-token',
            'X-Tenant': 'tenant-secret-value',
        },
        'cookies': [
            {'name': 'session', 'value': 'nested-cookie-secret', 'path': '/'},
        ],
        'local_storage': {'access_token': 'nested-storage-secret'},
        'session_storage': {'bootstrap': 'nested-session-secret'},
    })
    material = {'kind': 'generic', 'secret': session_secret}

    assert_no_credential_material_leaked(
        (material,),
        {
            'cookie_names': ['session'],
            'storage_keys': ['access_token', 'bootstrap'],
            'header_names': ['Authorization', 'X-Tenant'],
        },
    )

    for leaked in (
        'nested-browser-token',
        'Bearer nested-browser-token',
        'tenant-secret-value',
        'nested-cookie-secret',
        'nested-storage-secret',
        'nested-session-secret',
    ):
        with pytest.raises(AssertionError):
            assert_no_credential_material_leaked((material,), {'leaked': leaked})


def test_spa_normalizer_whitelists_metadata_and_drops_secret_values():
    raw = json.dumps({
        'schema': 'aegis.browser-spa-discovery.v1',
        'identity_ref': 'alice',
        'observations': [
            {
                'kind': 'browser-spa-summary',
                'identity_ref': 'alice',
                'target_origin': 'https://app.example.test',
                'page_title': 'Dashboard',
                'local_storage_keys': ['access_token', 'theme'],
                'session_storage_keys': ['workspace'],
                'cookies': [{
                    'name': 'session',
                    'value': 'must-never-survive-normalization',
                    'domain': 'app.example.test',
                    'path': '/',
                    'secure': True,
                    'http_only': True,
                    'same_site': 'Lax',
                    'session': True,
                }],
                'post_message_listener_count': 1,
                'inner_html_write_count': 2,
                'blocked_out_of_scope_request_count': 1,
                'blocked_websocket_count': 2,
                'blocked_webtransport_count': 3,
                'network_isolation': 'scope-validated-socks5-plus-cdp',
                'proxy_blocked_connection_count': 4,
                'proxy_allowed_connection_count': 7,
                'unknown_secret': 'drop-me',
            },
            {
                'kind': 'browser-http-endpoint',
                'url': 'https://app.example.test/api/profile?token=*',
                'method': 'GET',
                'resource_type': 'Fetch',
                'document_url': 'https://app.example.test/dashboard',
                'status': 200,
                'mime_type': 'application/json',
                'response_headers': {
                    'Content-Security-Policy': "default-src 'self'",
                    'Set-Cookie': 'session=must-not-persist',
                    'X-Internal-Secret': 'drop-me',
                },
                'body': {'secret': 'drop-me'},
            },
            {
                'kind': 'browser-graphql-operation',
                'endpoint': 'https://app.example.test/graphql',
                'method': 'POST',
                'document_url': 'https://app.example.test/dashboard',
                'operation_type': 'query',
                'operation_name': 'Viewer',
                'variable_keys': ['accountId'],
                'variables': {'accountId': 'secret-object-id'},
            },
        ],
    })

    normalized = normalize_native_output('browser.spa-discovery', raw)
    rendered = json.dumps(normalized, sort_keys=True)
    assert normalized['count'] == 3
    assert 'must-never-survive-normalization' not in rendered
    assert 'session=must-not-persist' not in rendered
    assert 'X-Internal-Secret' not in rendered
    assert 'secret-object-id' not in rendered
    assert 'drop-me' not in rendered
    summary = normalized['observations'][0]
    assert summary['local_storage_keys'] == ['access_token', 'theme']
    assert summary['cookies'][0]['name'] == 'session'
    assert summary['blocked_websocket_count'] == 2
    assert summary['blocked_webtransport_count'] == 3
    assert summary['network_isolation'] == 'scope-validated-socks5-plus-cdp'
    assert summary['proxy_blocked_connection_count'] == 4
    assert summary['proxy_allowed_connection_count'] == 7
    assert 'value' not in summary['cookies'][0]
    endpoint = normalized['observations'][1]
    assert endpoint['response_headers'] == {'content-security-policy': "default-src 'self'"}


@pytest.mark.django_db
def test_browser_surface_graph_persists_proven_initiator_flow_without_secret_values(project):
    scan = SimpleNamespace(
        id='11111111-1111-1111-1111-111111111111',
        project=project,
        asset_id='22222222-2222-2222-2222-222222222222',
        asset=SimpleNamespace(name='SPA Fixture'),
    )
    normalized = {
        'schema': 'aegis.native-observations.v1',
        'count': 5,
        'observations': [
            {
                'kind': 'browser-spa-summary',
                'identity_ref': 'alice',
                'target_origin': 'https://app.example.test',
                'profile_isolation': 'dedicated-ephemeral-user-data-dir',
                'credential_transport': 'same-origin-request-interception',
                'local_storage_keys': ['access_token'],
                'session_storage_keys': ['workspace'],
                'cookies': [{'name': 'session', 'secure': True, 'http_only': True}],
            },
            {'kind': 'browser-page-route', 'url': 'https://app.example.test/dashboard'},
            {
                'kind': 'browser-http-endpoint',
                'url': 'https://app.example.test/api/profile',
                'method': 'GET',
                'resource_type': 'Fetch',
                'document_url': 'https://app.example.test/dashboard',
                'status': 200,
                'mime_type': 'application/json',
                'response_headers': {},
            },
            {
                'kind': 'browser-graphql-operation',
                'endpoint': 'https://app.example.test/graphql',
                'method': 'POST',
                'document_url': 'https://app.example.test/dashboard',
                'operation_type': 'query',
                'operation_name': 'Viewer',
                'variable_keys': ['accountId'],
            },
            {'kind': 'browser-websocket-channel', 'url': 'wss://app.example.test/ws'},
        ],
    }

    result = project_browser_surface_graph(
        scan=scan,
        normalized=normalized,
        evidence_ref='33333333-3333-3333-3333-333333333333',
    )
    assert result['nodes_created'] >= 8

    kinds = set(SecurityGraphNode.objects.filter(project=project).values_list('kind', flat=True))
    assert {'asset', 'identity', 'session', 'page', 'endpoint', 'graphql_operation', 'websocket_channel', 'trust_boundary', 'data_flow'} <= kinds
    relations = set(SecurityGraphEdge.objects.filter(project=project).values_list('relation', flat=True))
    assert 'initiates_runtime_flow' in relations
    assert 'opens_channel' in relations
    assert 'bound_to_origin' in relations

    rendered = json.dumps(
        {
            'nodes': list(SecurityGraphNode.objects.filter(project=project).values('properties', 'provenance')),
            'edges': list(SecurityGraphEdge.objects.filter(project=project).values('properties', 'provenance', 'evidence_refs')),
        },
        default=str,
        sort_keys=True,
    )
    assert 'super-secret' not in rendered
