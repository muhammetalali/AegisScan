from __future__ import annotations

import os

import pytest

from fastapi_app.services import kali_recon_provider as provider


def test_provider_mode_defaults_to_legacy_and_kali_is_explicit(monkeypatch):
    monkeypatch.delenv('AEGIS_RECON_PROVIDER', raising=False)
    assert provider.provider_mode() == 'legacy'
    assert provider.should_use_kali_recon('recon.subfinder') is False

    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    assert provider.provider_mode() == 'kali'
    assert provider.should_use_kali_recon('recon.subfinder') is True
    assert provider.should_use_kali_recon('web.httpx') is False

    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'automatic')
    with pytest.raises(provider.KaliReconProviderError, match='legacy or kali'):
        provider.provider_mode()


def test_provider_url_is_strict_loopback_only(monkeypatch):
    valid = {
        'http://127.0.0.1:18765': 'http://127.0.0.1:18765',
    }
    for raw, expected in valid.items():
        monkeypatch.setenv('AEGIS_KALI_RECON_URL', raw)
        assert provider._base_url() == expected

    invalid = (
        'https://127.0.0.1:18765',
        'http://localhost:18765',
        'http://10.0.0.5:18765',
        'http://recon.internal:18765',
        'http://user:pass@127.0.0.1:18765',
        'http://127.0.0.1:18765/v1',
        'http://127.0.0.1:80',
        'http://127.0.0.1:18765?token=x',
    )
    for raw in invalid:
        monkeypatch.setenv('AEGIS_KALI_RECON_URL', raw)
        with pytest.raises(provider.KaliReconProviderError):
            provider._base_url()


def test_provider_auth_token_is_required_and_strict(monkeypatch):
    monkeypatch.delenv('AEGIS_KALI_RECON_AUTH_TOKEN', raising=False)
    with pytest.raises(provider.KaliReconProviderError, match='64-character lowercase hex token'):
        provider._auth_token()
    for invalid in ('short', 'A' * 64, 'g' * 64):
        monkeypatch.setenv('AEGIS_KALI_RECON_AUTH_TOKEN', invalid)
        with pytest.raises(provider.KaliReconProviderError, match='64-character lowercase hex token'):
            provider._auth_token()
    monkeypatch.setenv('AEGIS_KALI_RECON_AUTH_TOKEN', 'a' * 64)
    assert provider._auth_token() == 'a' * 64


def test_provider_transport_disables_environment_proxies(monkeypatch):
    monkeypatch.setenv('HTTP_PROXY', 'http://proxy.invalid:8080')
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:8080')
    captured = {}
    sentinel = object()

    def fake_build_opener(*handlers):
        captured['handlers'] = handlers
        return sentinel

    monkeypatch.setattr(provider.urllib.request, 'build_opener', fake_build_opener)
    assert provider._direct_opener() is sentinel
    proxy_handlers = [
        handler for handler in captured['handlers']
        if isinstance(handler, provider.urllib.request.ProxyHandler)
    ]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {}


def test_execute_rejects_non_recon_capability_before_transport(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    with pytest.raises(provider.KaliReconProviderError, match='not a Kali recon provider capability'):
        provider.execute_kali_recon(
            capability_id='web.httpx',
            target='example.invalid',
            options={},
            timeout_seconds=30,
            execution_ref='scan-1',
            authorization_ref='auth-1',
            scope_ref='project:p:asset:a',
            state_getter=None,
            poll_interval=0.1,
        )


def test_execute_requires_all_control_plane_bindings(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    fields = ('execution_ref', 'authorization_ref', 'scope_ref')
    base = {
        'capability_id': 'recon.subfinder',
        'target': 'example.invalid',
        'options': {},
        'timeout_seconds': 30,
        'execution_ref': 'scan-1',
        'authorization_ref': 'auth-1',
        'scope_ref': 'project:p:asset:a',
        'state_getter': None,
        'poll_interval': 0.1,
    }
    for field in fields:
        kwargs = dict(base)
        kwargs[field] = ''
        with pytest.raises(provider.KaliReconProviderError, match=f'{field} is required'):
            provider.execute_kali_recon(**kwargs)


def test_response_binding_and_provenance_are_fail_closed(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'kali')
    trust = {
        'AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION': '0.1.0',
        'AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT': 'b' * 40,
        'AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST': 'sha256:' + 'a' * 64,
        'AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST': 'sha256:' + 'c' * 64,
        'AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST': 'sha256:' + 'e' * 64,
        'AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST': 'sha256:' + 'd' * 64,
    }
    for name, value in trust.items():
        monkeypatch.setenv(name, value)

    def response(**overrides):
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
                'runtime_manifest_digest': 'sha256:' + 'd' * 64,
                'tool': 'subfinder',
                'tool_version': 'v2.16.0',
                'tool_source': 'go',
            },
        }
        payload.update(overrides)
        return payload

    def invoke_with(payload):
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

    result = invoke_with(response())
    assert result['tool'] == 'subfinder'
    assert result['runtime']['image_digest'] == trust['AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST']
    assert result['runtime']['provenance_authority'] == 'control-plane-deployment-pins'
    for payload in (
        response(execution_ref='other'),
        response(capability_id='recon.amass'),
        response(target='other.invalid'),
        response(runtime={'provider': 'legacy-native-worker'}),
        response(exit_code='0'),
        response(stdout=object()),
    ):
        with pytest.raises(provider.KaliReconProviderError):
            invoke_with(payload)


def test_control_registration_race_is_the_only_retryable_provider_error(monkeypatch):
    calls = []

    def transient(*args, **kwargs):
        calls.append(1)
        if len(calls) < 3:
            raise provider.KaliReconProviderError(
                'Kali recon provider rejected request (400): execution_ref is not active'
            )
        return {'status': 'ok', 'state': 'paused'}

    monkeypatch.setattr(provider, '_request_json', transient)
    monkeypatch.setattr(provider.time, 'sleep', lambda _: None)
    provider._control('scan-1', 'a' * 64, 'paused')
    assert len(calls) == 3

    calls.clear()

    def fatal(*args, **kwargs):
        calls.append(1)
        raise provider.KaliReconProviderError('Kali recon provider is unavailable')

    monkeypatch.setattr(provider, '_request_json', fatal)
    with pytest.raises(provider.KaliReconProviderError, match='unavailable'):
        provider._control('scan-1', 'a' * 64, 'paused')
    assert len(calls) == 1


def test_module_does_not_enable_provider_through_unrelated_environment(monkeypatch):
    monkeypatch.delenv('AEGIS_RECON_PROVIDER', raising=False)
    monkeypatch.setenv('AEGIS_KALI_RECON_URL', 'http://127.0.0.1:18765')
    monkeypatch.setenv('DATABASE_URL', 'postgres://should-not-select-provider')
    assert provider.provider_mode() == 'legacy'
    assert os.environ['DATABASE_URL']
