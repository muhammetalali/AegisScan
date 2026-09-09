from __future__ import annotations

from pathlib import Path

import pytest

from fastapi_app.services.api_runtime_launcher import _extract_bearer_config
from fastapi_app.services.capability_registry import get_capability, validate_capability_options
from fastapi_app.services.native_packaging import PACKAGED_NATIVE_CAPABILITIES
from fastapi_app.services.native_tool_runtime import NATIVE_TOOL_SPECS


def test_api_runtime_capability_is_real_packaged_and_bounded():
    capability = get_capability('api.openapi-runtime-conformance')
    assert capability.tool == 'aegis-api-runtime-conformance'
    assert capability.asset_types == ('api_endpoint',)
    assert capability.risk == 'active-low'
    assert capability.credential_mode == 'curl-bearer-config'
    assert set(capability.credential_kinds) == {'token', 'api_key', 'generic'}
    assert capability.id in PACKAGED_NATIVE_CAPABILITIES
    assert capability.id in NATIVE_TOOL_SPECS

    normalized = validate_capability_options(capability, {
        'spec_path': '/docs/openapi.json',
        'max_operations': 12,
        'max_response_bytes': 65536,
        'timeout_seconds': 5,
    })
    assert normalized['spec_path'] == '/docs/openapi.json'
    assert normalized['max_operations'] == 12
    assert normalized['max_response_bytes'] == 65536
    assert normalized['timeout_seconds'] == 5


def test_api_runtime_options_fail_closed():
    capability = get_capability('api.openapi-runtime-conformance')
    with pytest.raises(ValueError, match='spec_path'):
        validate_capability_options(capability, {'spec_path': 'https://other.example.test/openapi.json'})
    with pytest.raises(ValueError, match='max_operations'):
        validate_capability_options(capability, {'max_operations': 51})
    with pytest.raises(ValueError, match='Unsupported options'):
        validate_capability_options(capability, {'arbitrary_flags': '--dangerous'})


def test_launcher_extracts_only_single_aegis_bearer_config(tmp_path: Path):
    path = tmp_path / 'credential.curlrc'
    path.write_text('header = "Authorization: Bearer secret-token-123"\n', encoding='utf-8')
    assert _extract_bearer_config(str(path)) == 'secret-token-123'

    path.write_text('header = "X-Other: nope"\n', encoding='utf-8')
    with pytest.raises(ValueError, match='AegisScan bearer'):
        _extract_bearer_config(str(path))

    path.write_text('header = "Authorization: Bearer one"\nheader = "Authorization: Bearer two"\n', encoding='utf-8')
    with pytest.raises(ValueError, match='exactly one'):
        _extract_bearer_config(str(path))
