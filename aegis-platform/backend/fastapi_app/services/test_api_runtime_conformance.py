from __future__ import annotations

import json
from urllib.parse import urlsplit

import pytest

import fastapi_app.services.api_runtime_conformance as runtime
from fastapi_app.services.pinned_http import PinnedHTTPResponse


def _document() -> dict:
    return {
        'openapi': '3.1.0',
        'info': {'title': 'Runtime Fixture', 'version': '1'},
        'components': {
            'securitySchemes': {
                'BearerAuth': {'type': 'http', 'scheme': 'bearer'},
                'HeaderKey': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'},
                'QueryKey': {'type': 'apiKey', 'in': 'query', 'name': 'api_key'},
            },
            'schemas': {
                'Item': {
                    'type': 'object',
                    'required': ['id'],
                    'properties': {'id': {'type': 'string'}},
                },
            },
        },
        'paths': {
            '/items': {
                'get': {
                    'parameters': [{
                        'name': 'limit', 'in': 'query', 'required': True,
                        'schema': {'type': 'integer', 'minimum': 1},
                    }],
                    'responses': {
                        '200': {
                            'description': 'ok',
                            'content': {'application/json': {'schema': {'type': 'object', 'required': ['id'], 'properties': {'id': {'type': 'string'}}}}},
                        },
                    },
                },
            },
            '/shape': {
                'get': {
                    'responses': {
                        '200': {
                            'description': 'ok',
                            'content': {'application/json': {'schema': {'$ref': '#/components/schemas/Item'}}},
                        },
                    },
                },
            },
            '/secure': {
                'get': {
                    'security': [{'BearerAuth': []}],
                    'responses': {'200': {'description': 'ok'}},
                },
            },
            '/write': {
                'post': {
                    'responses': {'202': {'description': 'accepted'}},
                },
            },
        },
    }


def _response(url: str, status: int, payload: object | None = None, content_type: str = 'application/json') -> PinnedHTTPResponse:
    body = b'' if payload is None else json.dumps(payload).encode()
    return PinnedHTTPResponse(
        status=status,
        headers={'content-type': content_type},
        body=body,
        url=url,
        resolved_ip='203.0.113.10',
    )


def test_validate_runtime_executes_only_safe_methods_and_projects_semantic_findings(monkeypatch):
    calls: list[tuple[str, str, dict[str, str]]] = []

    def fake_request(method: str, url: str, *, headers=None, **_kwargs):
        headers = dict(headers or {})
        calls.append((method, url, headers))
        path = urlsplit(url).path
        query = urlsplit(url).query
        if path == '/items':
            # Both baseline and missing-required-query negative case return 200,
            # proving the required-parameter enforcement finding.
            return _response(url, 200, {'id': 'item-1' if query else 'fallback'})
        if path == '/shape':
            return _response(url, 200, {})
        if path == '/secure':
            assert headers.get('Authorization') == 'Bearer vault-token'
            return _response(url, 200, {'ok': True})
        raise AssertionError(f'unexpected runtime request: {method} {url}')

    monkeypatch.setattr(runtime, 'request_pinned', fake_request)
    payload = runtime.validate_runtime(
        _document(),
        'https://api.example.test',
        credential='vault-token',
        max_operations=10,
    )
    assert payload['schema'] == 'aegis.api-runtime-conformance.v1'
    assert all(method in {'GET', 'HEAD'} for method, _, _ in calls)
    assert not any('/write' in url for _, url, _ in calls)
    assert len([call for call in calls if urlsplit(call[1]).path == '/items']) == 2

    rules = {
        item['rule_id']
        for item in payload['observations']
        if item.get('kind') == 'api-runtime-security-finding'
    }
    assert 'api.runtime.required-query-not-enforced' in rules
    assert 'api.runtime.response-shape-mismatch' in rules
    assert 'vault-token' not in json.dumps(payload)


def test_secured_operation_is_skipped_without_credential(monkeypatch):
    calls: list[str] = []

    def fake_request(method: str, url: str, **_kwargs):
        calls.append(url)
        return _response(url, 200, {'id': 'ok'})

    monkeypatch.setattr(runtime, 'request_pinned', fake_request)
    payload = runtime.validate_runtime(_document(), 'https://api.example.test', max_operations=10)
    skips = [item for item in payload['observations'] if item.get('kind') == 'api-runtime-operation-skip']
    assert any(item['path'] == '/secure' and item['reason'] == 'credential-required' for item in skips)
    assert not any(urlsplit(url).path == '/secure' for url in calls)


def test_api_key_header_is_supported_but_query_key_is_not():
    document = _document()
    header_operation = {'security': [{'HeaderKey': []}]}
    headers, mode, reason = runtime._auth_headers(document, header_operation, 'secret')
    assert headers == {'X-API-Key': 'secret'}
    assert mode == 'api-key-header'
    assert reason == ''

    query_operation = {'security': [{'QueryKey': []}]}
    headers, mode, reason = runtime._auth_headers(document, query_operation, 'secret')
    assert headers == {}
    assert mode == 'skipped'
    assert reason == 'unsupported-security-scheme'


def test_request_builder_stays_on_origin_and_resolves_path_parameters():
    document = {
        'openapi': '3.1.0',
        'paths': {},
    }
    item = {
        'parameters': [{
            'name': 'item_id', 'in': 'path', 'required': True,
            'schema': {'type': 'string', 'example': 'a/b'},
        }],
    }
    operation = {'responses': {'200': {'description': 'ok'}}}
    url, _, _ = runtime._build_request(
        document, 'https://api.example.test/v1', '/items/{item_id}', item, operation,
    )
    assert url == 'https://api.example.test/v1/items/a%2Fb'

    with pytest.raises(ValueError, match='safe origin-relative'):
        runtime._build_request(document, 'https://api.example.test', 'https://evil.test/items', {}, operation)


def test_response_shape_validation_is_bounded_and_resolves_local_refs():
    document = _document()
    errors = runtime._shape_errors(document, {'$ref': '#/components/schemas/Item'}, {})
    assert errors == ['$: missing required property id']
