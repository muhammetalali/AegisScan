from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.cloud_target import canonical_cloud_target, parse_cloud_target
from fastapi_app.services.native_packaging import PACKAGED_NATIVE_CAPABILITIES
from fastapi_app.services.native_tool_runtime import (
    _credential_runtime_args,
    _native_environment,
    get_native_tool_spec,
)


def test_cloud_capability_is_credential_bound_and_packaged():
    capability = get_capability('cloud.read-only-posture')
    assert capability.tool == 'aegis-cloud-security'
    assert capability.asset_types == ('cloud_resource',)
    assert capability.risk == 'active-low'
    assert capability.scan_type == 'full_validation'
    assert capability.credential_mode == 'cloud-credentials-file'
    assert capability.credential_kinds == ('cloud_access_key',)
    assert capability.credential_required is True
    assert capability.id in PACKAGED_NATIVE_CAPABILITIES


@pytest.mark.parametrize(
    ('value', 'canonical'),
    [
        ('aws://123456789012', 'aws://123456789012'),
        ('azure://11111111-2222-3333-4444-555555555555', 'azure://11111111-2222-3333-4444-555555555555'),
        ('gcp://aegis-prod-123', 'gcp://aegis-prod-123'),
    ],
)
def test_cloud_target_contract(value: str, canonical: str):
    assert canonical_cloud_target(value) == canonical
    assert parse_cloud_target(value).canonical == canonical


@pytest.mark.parametrize('value', [
    'http://123456789012',
    'aws://1234',
    'aws://key@123456789012',
    'aws://123456789012/path',
    'azure://not-a-uuid',
    'gcp://UPPER_PROJECT',
])
def test_cloud_target_rejects_noncanonical_scope(value: str):
    with pytest.raises(ValueError):
        parse_cloud_target(value)


def test_cloud_credential_materialization_is_0600_and_not_inline_in_argv():
    spec = get_native_tool_spec('cloud.read-only-posture')
    secret = json.dumps({
        'provider': 'aws',
        'access_key_id': 'AKIAEXAMPLE',
        'secret_access_key': 'never-inline-this-secret',
        'region': 'us-east-1',
    })
    args, cleanup = _credential_runtime_args(
        spec,
        ({'kind': 'cloud_access_key', 'credential_ref': '00000000-0000-0000-0000-000000000001', 'secret': secret},),
    )
    try:
        assert args[0] == '--credentials-file'
        assert len(args) == 2
        assert secret not in ' '.join(args)
        path = Path(args[1])
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert json.loads(path.read_text(encoding='utf-8'))['provider'] == 'aws'
    finally:
        for value in cleanup:
            Path(value).unlink(missing_ok=True)


def test_cloud_runtime_strips_ambient_provider_credentials(monkeypatch):
    spec = get_native_tool_spec('cloud.read-only-posture')
    for name in (
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_PROFILE',
        'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET',
        'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLOUD_PROJECT', 'CLOUDSDK_CONFIG',
    ):
        monkeypatch.setenv(name, f'ambient-{name.lower()}')
    environment = _native_environment(spec)
    assert environment['NO_COLOR'] == '1'
    assert not ({
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_PROFILE',
        'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET',
        'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLOUD_PROJECT', 'CLOUDSDK_CONFIG',
    } & set(environment))


def test_cloud_runtime_rejects_wrong_or_invalid_material():
    spec = get_native_tool_spec('cloud.read-only-posture')
    with pytest.raises(ValueError, match='requires credential-bound execution'):
        _credential_runtime_args(spec, ())
    with pytest.raises(ValueError, match='requires a cloud_access_key credential'):
        _credential_runtime_args(spec, ({'kind': 'token', 'secret': '{}'},))
    with pytest.raises(ValueError, match='valid JSON'):
        _credential_runtime_args(spec, ({'kind': 'cloud_access_key', 'secret': 'not-json'},))
