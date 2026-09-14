from __future__ import annotations

import json

from fastapi_app.services.native_output_enrichment import normalize_enriched_native_output


def _surface(result: dict) -> dict:
    return next(item for item in result['observations'] if item.get('kind') == 'parameter-surface-summary')


def test_httpx_normalization_redacts_values_and_preserves_parameter_names():
    raw = json.dumps({
        'url': 'https://app.example.test/api/items?token=super-secret&id=42&id=43',
        'status_code': 200,
        'title': 'Items',
        'content_type': 'application/json',
        'webserver': 'nginx',
        'tech': ['FastAPI', 'nginx'],
    })
    result = normalize_enriched_native_output('web.httpx', raw)
    endpoint = result['observations'][0]
    assert endpoint['kind'] == 'web-http-service'
    assert endpoint['url'] == 'https://app.example.test/api/items?id=*&token=*'
    assert endpoint['query_parameter_names'] == ['id', 'token']
    assert endpoint['status'] == 200
    assert endpoint['technologies'] == ['FastAPI', 'nginx']
    assert result['enrichment']['values_persisted'] is False
    assert 'super-secret' not in json.dumps(result, sort_keys=True)
    assert '42' not in endpoint['url']
    surface = _surface(result)
    assert {item['name'] for item in surface['parameters']} == {'id', 'token'}


def test_katana_normalization_handles_request_response_schema_and_js_resources():
    raw = '\n'.join([
        json.dumps({
            'request': {
                'endpoint': 'https://app.example.test/api/search?q=private-value&page=3',
                'method': 'GET',
            },
            'response': {'status_code': 200},
            'tag': 'a',
        }),
        json.dumps({
            'request': {
                'endpoint': 'https://app.example.test/static/app.js?build=secret-build-id',
                'method': 'GET',
            },
            'response': {'status_code': 200},
            'tag': 'script',
        }),
    ])
    result = normalize_enriched_native_output('web.katana', raw)
    endpoint = next(item for item in result['observations'] if item.get('kind') == 'web-discovered-endpoint')
    script = next(item for item in result['observations'] if item.get('kind') == 'web-javascript-resource')
    assert endpoint['url'] == 'https://app.example.test/api/search?page=*&q=*'
    assert endpoint['query_parameter_names'] == ['page', 'q']
    assert script['url'] == 'https://app.example.test/static/app.js?build=*'
    assert script['query_parameter_names'] == ['build']
    assert 'private-value' not in json.dumps(result, sort_keys=True)
    assert 'secret-build-id' not in json.dumps(result, sort_keys=True)
    surface = _surface(result)
    assert surface['javascript_resource_count'] == 1
    assert {item['name'] for item in surface['parameters']} == {'build', 'page', 'q'}


def test_browser_spa_enrichment_uses_only_existing_runtime_metadata_and_redacts_values():
    raw = json.dumps({
        'schema': 'aegis.browser-spa-discovery.v1',
        'observations': [
            {
                'kind': 'browser-http-endpoint',
                'url': 'https://app.example.test/api/profile?token=browser-secret&view=full',
                'method': 'GET',
                'document_url': 'https://app.example.test/?workspace=tenant-secret',
                'resource_type': 'Fetch',
                'status': 200,
                'mime_type': 'application/json',
                'response_headers': {},
            },
            {
                'kind': 'browser-graphql-operation',
                'endpoint': 'https://app.example.test/graphql?trace=trace-secret',
                'method': 'POST',
                'document_url': 'https://app.example.test/',
                'operation_type': 'query',
                'operation_name': 'Viewer',
                'variable_keys': ['accountId', 'secretToken'],
            },
            {
                'kind': 'browser-javascript-resource',
                'url': 'https://app.example.test/static/app.js?build=build-secret',
                'source_map_url': 'https://app.example.test/static/app.js.map?rev=map-secret',
            },
        ],
    })
    result = normalize_enriched_native_output('browser.spa-discovery', raw)
    serialized = json.dumps(result, sort_keys=True)
    for secret in ('browser-secret', 'tenant-secret', 'trace-secret', 'build-secret', 'map-secret'):
        assert secret not in serialized
    endpoint = next(item for item in result['observations'] if item.get('kind') == 'browser-http-endpoint')
    assert endpoint['url'].endswith('token=*&view=*')
    assert endpoint['query_parameter_names'] == ['token', 'view']
    graphql = next(item for item in result['observations'] if item.get('kind') == 'browser-graphql-operation')
    assert graphql['variable_keys'] == ['accountId', 'secretToken']
    script = next(item for item in result['observations'] if item.get('kind') == 'browser-javascript-resource')
    assert script['url'].endswith('build=*')
    assert script['source_map_url'].endswith('rev=*')
    surface = _surface(result)
    by_name = {item['name']: item for item in surface['parameters']}
    assert {'accountId', 'secretToken', 'token', 'view', 'trace', 'build'} <= set(by_name)
    assert 'graphql-variable' in by_name['secretToken']['sources']
    assert surface['javascript_resource_count'] == 1
    assert surface['source_map_count'] == 1
    assert surface['values_persisted'] is False


def test_malformed_or_dangerous_urls_do_not_enter_enriched_observations():
    raw = '\n'.join([
        json.dumps({'url': 'file:///etc/passwd', 'status_code': 200}),
        json.dumps({'url': 'https://user:secret@app.example.test/private?x=y', 'status_code': 200}),
        json.dumps({'url': 'https://app.example.test/path?good=1&bad%0Aname=2', 'status_code': 200}),
    ])
    result = normalize_enriched_native_output('web.httpx', raw)
    services = [item for item in result['observations'] if item.get('kind') == 'web-http-service']
    assert len(services) == 1
    assert services[0]['url'] == 'https://app.example.test/path?good=*'
    assert services[0]['query_parameter_names'] == ['good']
    serialized = json.dumps(result, sort_keys=True)
    assert 'user:secret' not in serialized
    assert 'bad%0Aname' not in serialized


def test_non_enriched_capability_delegates_to_existing_normalizer_contract():
    result = normalize_enriched_native_output('recon.dnsenum', 'api.example.test 192.0.2.10')
    assert result['schema'] == 'aegis.native-observations.v1'
    assert any(item.get('kind') == 'dns-hostname' for item in result['observations'])
    assert 'enrichment' not in result
