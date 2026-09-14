from __future__ import annotations

import re

import pytest

from aegis.platform_client import PlatformClient, PlatformClientError


def _response(*, reused: bool = False) -> dict:
    return {
        'capability_id': 'network.nmap',
        'delegate_capability_id': None,
        'plugin': None,
        'policy_version': 'capability-execution.v4',
        'authorization_required': True,
        'evidence_required': True,
        'execution_mode': 'isolated-celery',
        'credential_context': {'credential_refs': []},
        'execution_contract': {
            'contract_version': '1.0',
            'policy_version': 'capability-execution.v4',
            'actor_ref': 'user:u1',
            'tenant_scope_ref': 'project:p1',
            'project_ref': 'project:p1',
            'asset_ref': 'asset:a1',
            'authorization_ref': 'authorization:auth1',
            'requested_capability_id': 'network.nmap',
            'capability_id': 'network.nmap',
            'methodology_refs': [],
            'allowed_options': {},
            'credential_bindings': [],
            'runner_profile': 'network',
            'execution_mode': 'isolated-celery',
            'risk_class': 'active-low',
            'depth': 'quick',
            'idempotency_key': 'idem-test-0001',
            'correlation_id': 'corr-test-0001',
            'idempotency_fingerprint': 'a' * 64,
            'policy_fingerprint': 'b' * 64,
        },
        'execution_contract_fingerprint': 'c' * 64,
        'correlation_id': 'corr-test-0001',
        'idempotency_reused': reused,
        'scan': {'id': 'scan-1', 'status': 'queued'},
    }


def test_execute_capability_uses_canonical_governed_endpoint_and_preserves_retry_identity(monkeypatch):
    client = PlatformClient('https://platform.example')
    captured = {}

    def request(method, path, payload=None):
        captured.update(method=method, path=path, payload=payload)
        return _response()

    monkeypatch.setattr(client, 'request', request)
    result = client.execute_capability(
        project_id='p1',
        asset_id='a1',
        capability_id='network.nmap',
        depth='quick',
        options={},
        credential_refs=[],
        idempotency_key='idem-test-0001',
        correlation_id='corr-test-0001',
    )

    assert captured == {
        'method': 'POST',
        'path': '/api/v1/capabilities/network.nmap/execute',
        'payload': {
            'project_id': 'p1',
            'asset_id': 'a1',
            'depth': 'quick',
            'options': {},
            'credential_refs': [],
            'idempotency_key': 'idem-test-0001',
            'correlation_id': 'corr-test-0001',
        },
    }
    assert result['scan']['id'] == 'scan-1'
    assert result['execution_contract']['policy_fingerprint'] == 'b' * 64


def test_execute_capability_generates_valid_idempotency_and_correlation_for_automation(monkeypatch):
    client = PlatformClient('https://platform.example')
    captured = {}

    def request(method, path, payload=None):
        captured.update(method=method, path=path, payload=payload)
        response = _response()
        response['execution_contract']['idempotency_key'] = payload['idempotency_key']
        response['execution_contract']['correlation_id'] = payload['correlation_id']
        response['correlation_id'] = payload['correlation_id']
        return response

    monkeypatch.setattr(client, 'request', request)
    client.execute_capability(project_id='p1', asset_id='a1', capability_id='network.nmap')

    assert re.fullmatch(r'client-[0-9a-f-]{36}', captured['payload']['idempotency_key'])
    assert re.fullmatch(r'client-corr-[0-9a-f-]{36}', captured['payload']['correlation_id'])


def test_execute_capability_rejects_unversioned_or_untrusted_response(monkeypatch):
    client = PlatformClient('https://platform.example')
    monkeypatch.setattr(client, 'request', lambda *_args, **_kwargs: {'scan': {'id': 'scan-1'}})

    with pytest.raises(PlatformClientError, match='versioned execution contract'):
        client.execute_capability(project_id='p1', asset_id='a1', capability_id='network.nmap')


def test_capability_plan_uses_server_planner(monkeypatch):
    client = PlatformClient('https://platform.example')
    captured = {}

    def request(method, path, payload=None):
        captured.update(method=method, path=path, payload=payload)
        return {
            'policy_version': 'capability-execution.v4',
            'asset_type': 'ip_address',
            'depth': 'quick',
            'total': 1,
            'ready': 1,
            'pending_packaging': 0,
            'plan': [
                {
                    'capability_id': 'network.nmap',
                    'tool': 'nmap',
                    'category': 'network-reconnaissance',
                    'risk': 'active-low',
                    'execution_ready': True,
                    'reason': 'packaged and eligible for governed execution',
                    'order': 1,
                }
            ],
        }

    monkeypatch.setattr(client, 'request', request)
    result = client.capability_plan('p1', 'a1', 'quick')

    assert captured['method'] == 'GET'
    assert captured['path'] == '/api/v1/capabilities/plan/a1?project_id=p1&depth=quick'
    assert result['plan'][0]['capability_id'] == 'network.nmap'
