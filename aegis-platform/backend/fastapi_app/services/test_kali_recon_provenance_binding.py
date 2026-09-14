from __future__ import annotations

import pytest

from fastapi_app.services import kali_recon_provider as provider


_RUNTIME_BY_TOOL = {
    'amass': ('v5.1.1', 'go'),
    'subfinder': ('v2.16.0', 'go'),
    'dnsenum': ('1.3.2-1', 'kali-apt'),
    'fierce': ('1.6.0-2', 'kali-apt'),
}
_TRUST = {
    'AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION': '0.1.0',
    'AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT': 'b' * 40,
    'AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST': 'sha256:' + 'a' * 64,
    'AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST': 'sha256:' + 'c' * 64,
    'AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST': 'sha256:' + 'e' * 64,
    'AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST': 'sha256:' + 'd' * 64,
}


def _set_trust_anchor(monkeypatch, **overrides):
    values = {**_TRUST, **overrides}
    for name, value in values.items():
        monkeypatch.setenv(name, value)


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
            'runtime_manifest_digest': 'sha256:' + 'd' * 64,
            'tool': tool,
            'tool_version': tool_version,
            'tool_source': tool_source,
        },
    }
    payload.update(overrides)
    return payload


def _invoke(monkeypatch, payload, *, capability_id: str = 'recon.subfinder', trust: bool = True):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    if trust:
        _set_trust_anchor(monkeypatch)
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
    result = _invoke(monkeypatch, payload, capability_id=capability_id)
    assert result['tool'] == tool
    assert result['runtime']['image_digest'] == _TRUST['AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST']
    assert result['runtime']['provenance_authority'] == 'control-plane-deployment-pins'


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
        _response(runtime={**runtime, 'runtime_manifest_digest': 'sha256:short'}),
    ):
        with pytest.raises(provider.KaliReconProviderError):
            _invoke(monkeypatch, payload)


@pytest.mark.parametrize('missing_name', tuple(_TRUST))
def test_complete_trust_anchor_is_required_before_transport(monkeypatch, missing_name):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    _set_trust_anchor(monkeypatch)
    monkeypatch.delenv(missing_name)
    called = False

    def transport(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError('transport must not run without complete trust anchor')

    monkeypatch.setattr(provider, '_request_json', transport)
    with pytest.raises(provider.KaliReconProviderError, match=f'{missing_name} is required'):
        provider.execute_kali_recon(
            capability_id='recon.subfinder',
            target='example.invalid',
            options={},
            timeout_seconds=30,
            execution_ref='scan-1',
            authorization_ref='auth-1',
            scope_ref='project:p:asset:a',
            state_getter=None,
            poll_interval=0.01,
        )
    assert called is False


@pytest.mark.parametrize(
    ('env_name', 'good_value', 'bad_value', 'field'),
    (
        ('AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION', '0.1.0', '0.2.0', 'runner_version'),
        ('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', 'b' * 40, 'f' * 40, 'build_commit'),
        (
            'AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST',
            'sha256:' + 'a' * 64,
            'sha256:' + 'f' * 64,
            'base_image_digest',
        ),
        (
            'AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST',
            'sha256:' + 'c' * 64,
            'sha256:' + 'f' * 64,
            'tool_manifest_digest',
        ),
        (
            'AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST',
            'sha256:' + 'd' * 64,
            'sha256:' + 'f' * 64,
            'runtime_manifest_digest',
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
    _set_trust_anchor(monkeypatch, **{env_name: good_value})
    assert _invoke(monkeypatch, payload, trust=False)['tool'] == 'subfinder'
    monkeypatch.setenv(env_name, bad_value)
    with pytest.raises(provider.KaliReconProviderError, match=f'pinned {field} mismatch'):
        _invoke(monkeypatch, payload, trust=False)


def test_execution_image_digest_comes_only_from_control_plane_anchor(monkeypatch):
    payload = _response()
    payload['runtime']['image_digest'] = 'sha256:' + 'f' * 64
    result = _invoke(monkeypatch, payload)
    assert result['runtime']['image_digest'] == _TRUST['AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST']
    assert result['runtime']['image_digest'] != payload['runtime']['image_digest']


@pytest.mark.parametrize(
    ('env_name', 'invalid_value'),
    (
        ('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', 'not-a-commit'),
        ('AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST', 'sha256:short'),
        ('AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST', 'sha256:short'),
        ('AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST', 'sha256:short'),
        ('AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST', 'sha256:short'),
    ),
)
def test_invalid_deployment_pin_configuration_fails_closed(monkeypatch, env_name, invalid_value):
    _set_trust_anchor(monkeypatch, **{env_name: invalid_value})
    with pytest.raises(provider.KaliReconProviderError, match=f'{env_name} is invalid'):
        _invoke(monkeypatch, _response(), trust=False)
