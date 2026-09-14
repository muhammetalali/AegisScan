from __future__ import annotations

from contextlib import contextmanager

import pytest

from fastapi_app.services import wstg_native_capabilities as wstg
from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.native_tool_runtime import NATIVE_TOOL_SPECS
from fastapi_app.services.pinned_http import PinnedHTTPResponse


def _response(status: int = 200, body: bytes = b'ok', headers=None) -> PinnedHTTPResponse:
    return PinnedHTTPResponse(
        status=status,
        headers=dict(headers or {}),
        body=body,
        url='https://example.test/',
        resolved_ip='203.0.113.10',
    )


def test_live_gap_capabilities_are_internal_and_registered_with_web_profile():
    for capability_id in (
        'web.http-method-policy',
        'web.duplicate-parameter-semantics',
        'web.ssrf-canary-validation',
        'tls.posture',
    ):
        capability = get_capability(capability_id)
        assert capability.runner_profile == 'web'
        assert capability.authorization_required is True
        assert capability.evidence_required is True
        assert capability.adapter == 'internal-validator'
        assert capability_id in wstg.WSTG_INTERNAL_SPECS
        assert capability_id not in NATIVE_TOOL_SPECS


def test_http_method_policy_sends_only_safe_methods(monkeypatch):
    methods = []

    def fake_request(method, target, **kwargs):
        methods.append(method)
        headers = {'allow': 'GET, HEAD, OPTIONS, POST'} if method == 'OPTIONS' else {}
        return _response(headers=headers)

    monkeypatch.setattr(wstg, 'request_pinned', fake_request)
    observation = wstg._method_policy('https://example.test/')
    assert methods == ['OPTIONS', 'HEAD', 'GET']
    assert observation['unsafe_methods_sent'] is False
    assert observation['allow_methods'] == ['GET', 'HEAD', 'OPTIONS', 'POST']
    assert observation['final_decision'] is False


def test_duplicate_parameter_probe_is_bounded_and_order_sensitive(monkeypatch):
    requested = []

    def fake_request(method, target, **kwargs):
        requested.append((method, target))
        if 'aegis_hpp_probe=1&aegis_hpp_probe=2' in target:
            return _response(body=b'forward')
        if 'aegis_hpp_probe=2&aegis_hpp_probe=1' in target:
            return _response(body=b'reverse')
        return _response(body=b'baseline')

    monkeypatch.setattr(wstg, 'request_pinned', fake_request)
    observation = wstg._duplicate_parameter_semantics('https://example.test/path?keep=1#client-only')
    assert [item[0] for item in requested] == ['GET', 'GET', 'GET']
    assert all('keep=1' in item[1] for item in requested)
    assert all('#client-only' not in item[1] for item in requested)
    assert observation['synthetic_parameter'] == 'aegis_hpp_probe'
    assert observation['order_sensitive_observed'] is True
    assert observation['final_decision'] is False


def test_ssrf_probe_refuses_unbound_oast_callback():
    observation = wstg._ssrf_canary_validation('https://example.test/')
    assert observation['abstained'] is True
    assert observation['callback_attempted'] is False
    assert observation['ssrf_confirmed'] is False
    assert 'OAST' in observation['abstention_reason']


def test_internal_normalizer_forces_observation_only():
    raw = '{"observations":[{"capability_id":"web.http-method-policy","wstg_id":"forged","final_decision":true,"observation_only":false,"statuses":{"GET":200}}]}'
    normalized = wstg.normalize_wstg_internal_output('web.http-method-policy', raw)
    assert normalized['count'] == 1
    row = normalized['observations'][0]
    assert row['wstg_id'] == 'WSTG-CONF-06'
    assert row['final_decision'] is False
    assert row['observation_only'] is True


def test_tls_posture_abstains_for_plain_http():
    class Destination:
        resolved_ips = ('203.0.113.10',)
        port = 80
        host = 'example.test'

    observation = wstg._tls_posture('http://example.test/', Destination())
    assert observation['abstained'] is True
    assert observation['final_decision'] is False


def test_runtime_dispatch_keeps_authorization_pinning(monkeypatch):
    events = []

    @contextmanager
    def fake_operation(target):
        events.append(('pin', target))
        class Destination:
            resolved_ips = ('203.0.113.10',)
            port = 443
            host = 'example.test'
        yield Destination()

    monkeypatch.setattr(wstg, 'validate_authorized_web_target', lambda target: target)
    monkeypatch.setattr(wstg, 'pinned_http_operation', fake_operation)
    monkeypatch.setattr(wstg, '_method_policy', lambda target: {**wstg._base('web.http-method-policy'), 'unsafe_methods_sent': False})

    result = wstg.run_wstg_internal_capability('web.http-method-policy', 'https://example.test/', {})
    assert events == [('pin', 'https://example.test/')]
    assert result.exit_code == 0
    assert 'WSTG-CONF-06' in result.stdout


def test_internal_capabilities_reject_options_and_credentials():
    with pytest.raises(ValueError, match='does not accept runtime options'):
        wstg.run_wstg_internal_capability('web.http-method-policy', 'https://example.test/', {'x': 1})
    with pytest.raises(ValueError, match='does not accept credential material'):
        wstg.run_wstg_internal_capability(
            'web.http-method-policy',
            'https://example.test/',
            {},
            credential_materials=({'kind': 'token', 'secret': 'x'},),
        )
