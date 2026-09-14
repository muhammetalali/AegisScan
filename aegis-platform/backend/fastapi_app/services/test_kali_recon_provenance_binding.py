from __future__ import annotations

import pytest

from fastapi_app.services import kali_recon_provider as provider


def _response(**overrides):
    payload = {
        'schema_version': 1,
        'status': 'completed',
        'execution_ref': 'scan-1',
        'capability_id': 'recon.subfinder',
        'target': 'example.invalid',
        'tool': 'subfinder',
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
            'tool': 'subfinder',
            'tool_version': 'v2.16.0',
            'tool_source': 'go',
        },
    }
    payload.update(overrides)
    return payload


def _invoke(monkeypatch, payload):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    monkeypatch.setattr(provider, '_request_json', lambda *args, **kwargs: payload)
    return provider.execute_kali_recon(
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


def test_recon_runtime_provenance_is_structurally_fail_closed(monkeypatch):
    assert _invoke(monkeypatch, _response())['runtime']['profile'] == 'recon'
    runtime = _response()['runtime']
    for payload in (
        _response(tool='amass'),
        _response(runtime={**runtime, 'provider': 'legacy-native-worker'}),
        _response(runtime={**runtime, 'profile': 'web'}),
        _response(runtime={**runtime, 'tool': 'amass'}),
        _response(runtime={**runtime, 'build_commit': 'invalid'}),
        _response(runtime={**runtime, 'base_image_digest': 'sha256:short'}),
        _response(runtime={**runtime, 'tool_manifest_digest': 'sha256:short'}),
    ):
        with pytest.raises(provider.KaliReconProviderError):
            _invoke(monkeypatch, payload)


def test_deployment_pin_rejects_authenticated_runtime_drift(monkeypatch):
    payload = _response()
    monkeypatch.setenv('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', 'b' * 40)
    assert _invoke(monkeypatch, payload)['tool'] == 'subfinder'
    monkeypatch.setenv('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', 'd' * 40)
    with pytest.raises(provider.KaliReconProviderError, match='pinned build_commit mismatch'):
        _invoke(monkeypatch, payload)
