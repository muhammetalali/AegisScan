from __future__ import annotations

import pytest

from fastapi_app.services import kali_recon_provider as provider


_RUNTIME_BY_TOOL = {
    'amass': ('v5.1.1', 'go'),
    'subfinder': ('v2.16.0', 'go'),
    'dnsenum': ('1.3.2-1', 'kali-apt'),
    'fierce': ('1.6.0-2', 'kali-apt'),
}


def _response(*, capability_id: str = 'recon.subfinder', tool: str = 'subfinder', **overrides):
    tool_version, tool_source = _RUNTIME_BY_TOOL[tool]
    payload = {
        'schema_version': 1,
        'status': 'completed',
        'execution_ref': 'scan-1',
        'capability_id': capability_id,
        'target': 'example.invalid',
        'tool': tool,
        'exit_code': 0,
        'stdout': '',
        'stderr': '',
        'runtime': {
            'provider': 'aegis-kali-recon',
            'profile': 'recon',
            'runner_version': '0.1.0',
            'base_image_digest': 'sha256:' + 'a' * 64,
            'build_commit': 'b' * 40,
            'tool_manifest_digest': 'sha256:' + 'c' * 64,
            'tool': tool,
            'tool_version': tool_version,
            'tool_source': tool_source,
        },
    }
    payload.update(overrides)
    return payload


def _invoke(monkeypatch, payload, *, capability_id: str = 'recon.subfinder'):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    monkeypatch.setattr(provider, '_request_json', lambda *args, **kwargs: payload)
    return provider.execute_kali_recon(
        capability_id=capability_id,
        target='example.invalid',
        options={},
        timeout_seconds=30,
        execution_ref='scan-1',
        authorization_ref='auth-1',
        scope_ref='project:p:asset:a',
        state_getter=None,
        poll_interval=0.01,
    )


@pytest.mark.parametrize(
    ('capability_id', 'tool'),
    (
        ('recon.amass', 'amass'),
        ('recon.subfinder', 'subfinder'),
        ('recon.dnsenum', 'dnsenum'),
        ('recon.fierce', 'fierce'),
    ),
)
def test_each_recon_capability_is_bound_to_its_runtime_tool(monkeypatch, capability_id, tool):
    payload = _response(capability_id=capability_id, tool=tool)
    assert _invoke(monkeypatch, payload, capability_id=capability_id)['tool'] == tool


def test_recon_runtime_provenance_is_structurally_fail_closed(monkeypatch):
    assert _invoke(monkeypatch, _response())['runtime']['profile'] == 'recon'
    runtime = _response()['runtime']
    for payload in (
        _response(tool='amass', capability_id='recon.subfinder'),
        _response(runtime={**runtime, 'provider': 'legacy-native-worker'}),
        _response(runtime={**runtime, 'profile': 'web'}),
        _response(runtime={**runtime, 'tool': 'amass'}),
        _response(runtime={**runtime, 'runner_version': ''}),
        _response(runtime={**runtime, 'tool_version': ''}),
        _response(runtime={**runtime, 'tool_source': ''}),
        _response(runtime={**runtime, 'build_commit': 'invalid'}),
        _response(runtime={**runtime, 'base_image_digest': 'sha256:short'}),
        _response(runtime={**runtime, 'tool_manifest_digest': 'sha256:short'}),
    ):
        with pytest.raises(provider.KaliReconProviderError):
            _invoke(monkeypatch, payload)


@pytest.mark.parametrize(
    ('env_name', 'good_value', 'bad_value', 'field'),
    (
        ('AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION', '0.1.0', '0.2.0', 'runner_version'),
        ('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', 'b' * 40, 'd' * 40, 'build_commit'),
        (
            'AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST',
            'sha256:' + 'a' * 64,
            'sha256:' + 'd' * 64,
            'base_image_digest',
        ),
        (
            'AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST',
            'sha256:' + 'c' * 64,
            'sha256:' + 'd' * 64,
            'tool_manifest_digest',
        ),
    ),
)
def test_deployment_pins_reject_authenticated_runtime_drift(
    monkeypatch,
    env_name,
    good_value,
    bad_value,
    field,
):
    payload = _response()
    monkeypatch.setenv(env_name, good_value)
    assert _invoke(monkeypatch, payload)['tool'] == 'subfinder'
    monkeypatch.setenv(env_name, bad_value)
    with pytest.raises(provider.KaliReconProviderError, match=f'pinned {field} mismatch'):
        _invoke(monkeypatch, payload)


@pytest.mark.parametrize(
    ('env_name', 'invalid_value'),
    (
        ('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', 'not-a-commit'),
        ('AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST', 'sha256:short'),
        ('AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST', 'sha256:short'),
    ),
)
def test_invalid_deployment_pin_configuration_fails_closed(monkeypatch, env_name, invalid_value):
    monkeypatch.setenv(env_name, invalid_value)
    with pytest.raises(provider.KaliReconProviderError, match=f'{env_name} is invalid'):
        _invoke(monkeypatch, _response())
