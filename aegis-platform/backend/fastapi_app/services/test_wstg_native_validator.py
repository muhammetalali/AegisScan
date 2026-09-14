from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from fastapi_app.services import wstg_native_validator as validator


class FakePinned:
    def __init__(self, responses):
        self.responses = list(responses)
        self.destination = SimpleNamespace(resolved_ips=('127.0.0.1',), port=443, host='example.test')

    def operation(self, _target):
        parent = self
        class Context:
            def __enter__(self):
                return parent.destination
            def __exit__(self, *_args):
                return False
        return Context()

    def request(self, _method, url, **_kwargs):
        if not self.responses:
            raise AssertionError(f'unexpected request: {url}')
        return self.responses.pop(0)


def response(status=200, body=b'ok', headers=None, content_type='text/plain'):
    headers = dict(headers or {})
    if content_type:
        headers.setdefault('content-type', content_type)
    return SimpleNamespace(
        status=status,
        body=body,
        headers=headers,
        content_type=content_type,
    )


def test_http_method_policy_reports_dangerous_advertised_method(monkeypatch):
    fake = FakePinned([response(headers={'allow': 'GET, TRACE, OPTIONS'})])
    monkeypatch.setattr(validator, 'pinned_http_operation', fake.operation)
    monkeypatch.setattr(validator, 'request_pinned', fake.request)
    result = validator.validate_http_method_policy('https://example.test/')
    assert result['capability_id'] == 'web.http-method-policy'
    findings = [x for x in result['observations'] if x.get('kind') == 'wstg-native-finding']
    assert [x['rule_id'] for x in findings] == ['wstg.http-method-dangerous-advertisement']


def test_duplicate_parameter_unstable_baseline_fails_closed(monkeypatch):
    fake = FakePinned([response(body=b'first'), response(body=b'second')])
    monkeypatch.setattr(validator, 'pinned_http_operation', fake.operation)
    monkeypatch.setattr(validator, 'request_pinned', fake.request)
    result = validator.validate_duplicate_parameter_semantics(
        'https://example.test/items?id=1', 'id'
    )
    summary = result['observations'][0]
    assert summary['status'] == 'inconclusive'
    assert not any(x.get('kind') == 'wstg-native-finding' for x in result['observations'])


def test_duplicate_parameter_order_sensitive_emits_finding(monkeypatch):
    fake = FakePinned([
        response(body=b'stable'),
        response(body=b'stable'),
        response(body=b'first-order'),
        response(body=b'second-order'),
    ])
    monkeypatch.setattr(validator, 'pinned_http_operation', fake.operation)
    monkeypatch.setattr(validator, 'request_pinned', fake.request)
    result = validator.validate_duplicate_parameter_semantics(
        'https://example.test/items?id=1', 'id'
    )
    findings = [x for x in result['observations'] if x.get('kind') == 'wstg-native-finding']
    assert [x['rule_id'] for x in findings] == ['wstg.duplicate-parameter-order-sensitive']
    serialized = json.dumps(result, sort_keys=True)
    assert 'aegis-alpha' not in serialized
    assert 'aegis-beta' not in serialized


def test_ssrf_unconfigured_is_inconclusive(monkeypatch):
    monkeypatch.delenv('AEGIS_SSRF_CANARY_BASE_URL', raising=False)
    monkeypatch.delenv('AEGIS_SSRF_CANARY_CONTROL_TOKEN', raising=False)
    result = validator.validate_ssrf_canary(
        'https://example.test/fetch?url=https%3A%2F%2Fexample.test', 'url'
    )
    assert result['observations'][0]['status'] == 'inconclusive'
    assert not any(x.get('kind') == 'wstg-native-finding' for x in result['observations'])


def test_ssrf_callback_observed_persists_only_token_fingerprint(monkeypatch):
    token = 'a' * 64
    monkeypatch.setenv('AEGIS_SSRF_CANARY_BASE_URL', 'https://canary.example.test')
    monkeypatch.setenv('AEGIS_SSRF_CANARY_CONTROL_TOKEN', 'b' * 64)
    monkeypatch.setattr(validator.secrets, 'token_hex', lambda _n: token)
    calls = []
    def fake_canary(_base, _control, path, payload=None):
        calls.append((path, payload))
        if path.endswith('/register'):
            return {'status': 'registered'}
        return {'status': 'registered', 'observed': True}
    monkeypatch.setattr(validator, '_canary_request', fake_canary)
    fake = FakePinned([response(status=204, body=b'')])
    monkeypatch.setattr(validator, 'pinned_http_operation', fake.operation)
    monkeypatch.setattr(validator, 'request_pinned', fake.request)
    result = validator.validate_ssrf_canary(
        'https://example.test/fetch?url=https%3A%2F%2Fexample.test', 'url'
    )
    assert any(x.get('rule_id') == 'wstg.ssrf-canary-callback-observed' for x in result['observations'])
    serialized = json.dumps(result, sort_keys=True)
    assert token not in serialized
    assert validator.hashlib.sha256(token.encode('ascii')).hexdigest() in serialized
    assert calls[0][1] == {'token': token}


def test_http_tls_target_emits_cleartext_transport_finding():
    result = validator.validate_tls_posture('http://example.test/')
    assert any(x.get('rule_id') == 'wstg.cleartext-http-transport' for x in result['observations'])


@pytest.mark.parametrize('value', ['bad name', '../x', 'a' * 129, 'x\nheader'])
def test_parameter_names_are_strictly_bounded(value):
    with pytest.raises(ValueError):
        validator._selected_parameter('https://example.test/', value)
