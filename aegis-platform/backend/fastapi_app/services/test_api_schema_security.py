from __future__ import annotations

import json

import pytest

from fastapi_app.services.api_schema_security import analyze_bytes, parse_document, schema_url


def _document() -> bytes:
    return json.dumps({
        'openapi': '3.1.0',
        'info': {'title': 'Aegis API Fixture', 'version': '1.0.0'},
        'components': {
            'securitySchemes': {
                'BearerAuth': {'type': 'http', 'scheme': 'bearer'},
                'LegacyQueryKey': {'type': 'apiKey', 'in': 'query', 'name': 'api_key'},
            },
        },
        'security': [{'BearerAuth': []}],
        'paths': {
            '/health': {'get': {'responses': {'200': {'description': 'ok'}}}},
            '/public-write': {
                'post': {
                    'security': [],
                    'responses': {'202': {'description': 'accepted'}},
                },
            },
            '/broken-auth': {
                'get': {
                    'security': [{'MissingScheme': []}],
                    'responses': {'200': {'description': 'ok'}},
                },
            },
        },
    }).encode()


def test_analyze_openapi_emits_bounded_semantic_findings():
    payload = analyze_bytes(_document(), 'https://api.example.test/openapi.json')
    assert payload['schema'] == 'aegis.api-schema-security.v1'
    summary = payload['observations'][0]
    assert summary['kind'] == 'api-schema-summary'
    assert summary['path_count'] == 3
    assert summary['operation_count'] == 3
    assert len(summary['document_sha256']) == 64

    findings = [item for item in payload['observations'] if item['kind'] == 'api-schema-security-finding']
    rules = {item['rule_id'] for item in findings}
    assert 'api.openapi.api-key-in-query' in rules
    assert 'api.openapi.undefined-security-scheme' in rules
    assert 'api.openapi.explicit-public-state-change' in rules
    public_write = next(item for item in findings if item['rule_id'] == 'api.openapi.explicit-public-state-change')
    assert public_write['method'] == 'POST'
    assert public_write['path'] == '/public-write'
    assert public_write['confidence'] == 'medium'


def test_swagger_2_is_accepted():
    document = parse_document(json.dumps({
        'swagger': '2.0',
        'info': {'title': 'Legacy', 'version': '1'},
        'paths': {},
        'securityDefinitions': {'Basic': {'type': 'basic'}},
    }).encode())
    assert document['swagger'] == '2.0'


def test_non_openapi_document_is_rejected():
    with pytest.raises(ValueError, match='OpenAPI'):
        parse_document(b'{"paths": {}}')


def test_schema_path_must_remain_on_authorized_origin():
    assert schema_url('https://api.example.test/v1', '/openapi.json') == 'https://api.example.test/openapi.json'
    with pytest.raises(ValueError, match='absolute path'):
        schema_url('https://api.example.test/v1', 'https://other.example.test/openapi.json')
    with pytest.raises(ValueError, match='absolute path'):
        schema_url('https://api.example.test/v1', '../openapi.json')


def test_path_and_operation_limits_fail_closed():
    oversized_paths = {f'/p/{index}': {} for index in range(10001)}
    body = json.dumps({'openapi': '3.0.3', 'info': {'title': 'x', 'version': '1'}, 'paths': oversized_paths}).encode()
    with pytest.raises(ValueError, match='10000 paths'):
        analyze_bytes(body, 'https://api.example.test/openapi.json')


def test_api_schema_subprocess_uses_bound_origin_with_pinned_dns(monkeypatch):
    from fastapi_app.services import api_schema_security, pinned_http
    from fastapi_app.services.pinned_http import PinnedHTTPResponse

    checked = []
    def checked_scope(value, **kwargs):
        checked.append((value, kwargs))
        assert kwargs['approved_target'] == 'https://api.lab.test/app'
        assert kwargs['approved_addresses'] == ('93.184.216.34',)
        return ('93.184.216.34',)

    def offline_fixture(url, **kwargs):
        assert pinned_http._OPERATION_DESTINATION.get() is not None
        assert pinned_http._OPERATION_DESTINATION.get().resolved_ips == ('93.184.216.34',)
        return PinnedHTTPResponse(200, {'content-type': 'application/json'}, _document(), url, '93.184.216.34')

    monkeypatch.setattr(pinned_http, 'require_authorized_target', checked_scope)
    monkeypatch.setattr(api_schema_security, 'get_pinned_same_origin', offline_fixture)
    url, body, content_type = api_schema_security.fetch_schema(
        'https://api.lab.test/app', '/openapi.json', 65536, 10,
        approved_target='https://api.lab.test/app',
        approved_addresses=('93.184.216.34',),
    )
    assert url == 'https://api.lab.test/openapi.json'
    assert body == _document()
    assert content_type == 'application/json'
    assert len(checked) >= 1
    with pytest.raises(ValueError, match='does not cover'):
        api_schema_security.fetch_schema(
            'https://other.lab.test/app', '/openapi.json', 65536, 10,
            approved_target='https://api.lab.test/app',
            approved_addresses=('93.184.216.34',),
        )
