from __future__ import annotations

from fastapi_app.services.capability_registry import get_capability, validate_capability_options
from fastapi_app.services.native_finding_projection import api_schema_finding_specs
from fastapi_app.services.native_output_normalizer import normalize_native_output


def test_api_schema_capability_is_registered_and_bounded():
    capability = get_capability('api.openapi-contract-security')
    assert capability.tool == 'aegis-api-schema-security'
    assert capability.category == 'api-security'
    assert capability.risk == 'active-low'
    assert set(capability.asset_types) == {'api_endpoint', 'website'}
    normalized = validate_capability_options(capability, {})
    assert normalized == {
        'spec_path': '/openapi.json',
        'max_spec_bytes': 1048576,
        'timeout_seconds': 10,
    }


def test_api_schema_preflight_rejects_cross_origin_or_relative_spec_paths():
    capability = get_capability('api.openapi-contract-security')
    for value in ('https://evil.example/openapi.json', '../openapi.json', '//evil.example/openapi.json'):
        try:
            validate_capability_options(capability, {'spec_path': value})
        except ValueError as exc:
            assert 'spec_path' in str(exc)
        else:
            raise AssertionError(f'unsafe spec_path accepted: {value}')


def test_api_schema_normalization_and_projection_preserve_distinct_locations():
    raw = '''{
      "schema":"aegis.api-schema-security.v1",
      "observations":[
        {"kind":"api-schema-summary","path_count":2,"operation_count":2},
        {"kind":"api-schema-security-finding","rule_id":"api.openapi.undefined-security-scheme","title":"Undefined auth A","description":"A","severity":"medium","confidence":"high","category":"api-security","remediation":"Define A","location":"paths./a.get.security","method":"GET","path":"/a"},
        {"kind":"api-schema-security-finding","rule_id":"api.openapi.undefined-security-scheme","title":"Undefined auth B","description":"B","severity":"medium","confidence":"high","category":"api-security","remediation":"Define B","location":"paths./b.get.security","method":"GET","path":"/b"}
      ]
    }'''
    normalized = normalize_native_output('api.openapi-contract-security', raw)
    assert normalized['count'] == 3
    specs = api_schema_finding_specs(normalized)
    assert len(specs) == 2
    assert specs[0].rule_id == specs[1].rule_id
    assert specs[0].identity_key != specs[1].identity_key
