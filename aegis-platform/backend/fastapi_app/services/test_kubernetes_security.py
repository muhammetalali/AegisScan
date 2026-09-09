from __future__ import annotations

import base64

import pytest
import yaml

from fastapi_app.services import kubernetes_security, pinned_http
from fastapi_app.services.kubernetes_security import (
    KubernetesSecurityError,
    KubernetesTransport,
    analyze_resources,
    canonical_server,
    load_kubeconfig,
    rbac_findings,
    workload_findings,
)
from fastapi_app.services.pinned_http import PinnedHTTPDestination, PinnedHTTPResponse


def test_canonical_server_requires_clean_https_target():
    assert canonical_server('https://KUBE.EXAMPLE.TEST:6443/') == 'https://kube.example.test:6443'
    for value in (
        'http://kube.example.test:6443',
        'https://user:pass@kube.example.test',
        'https://kube.example.test?x=1',
        'https://kube.example.test/#fragment',
    ):
        with pytest.raises(KubernetesSecurityError):
            canonical_server(value)


def test_workload_rules_emit_only_explicit_risky_settings():
    pod = {
        'metadata': {'namespace': 'payments', 'name': 'unsafe-pod'},
        'spec': {
            'hostPID': True,
            'hostNetwork': True,
            'volumes': [{'name': 'host', 'hostPath': {'path': '/var/lib'}}],
            'containers': [{
                'name': 'app',
                'securityContext': {
                    'privileged': True,
                    'allowPrivilegeEscalation': True,
                    'runAsUser': 0,
                    'capabilities': {'add': ['ALL']},
                },
            }],
        },
    }
    findings = workload_findings('Pod', pod)
    rules = {item['rule_id'] for item in findings}
    assert rules == {
        'kubernetes.workload.hostpid',
        'kubernetes.workload.hostnetwork',
        'kubernetes.workload.hostpath-volume',
        'kubernetes.workload.privileged-container',
        'kubernetes.workload.allow-privilege-escalation',
        'kubernetes.workload.explicit-root',
        'kubernetes.workload.capabilities-all',
    }
    assert all(item['namespace'] == 'payments' for item in findings)


def test_rbac_rules_bind_wildcard_and_default_cluster_admin():
    roles = [{
        'metadata': {'name': 'wild'},
        'rules': [{'apiGroups': ['*'], 'resources': ['*'], 'verbs': ['*']}],
    }]
    bindings = [
        {
            'metadata': {'name': 'wild-binding'},
            'roleRef': {'kind': 'ClusterRole', 'name': 'wild'},
            'subjects': [{'kind': 'ServiceAccount', 'name': 'scanner', 'namespace': 'aegis'}],
        },
        {
            'metadata': {'name': 'bad-admin'},
            'roleRef': {'kind': 'ClusterRole', 'name': 'cluster-admin'},
            'subjects': [{'kind': 'ServiceAccount', 'name': 'default', 'namespace': 'payments'}],
        },
    ]
    rules = {item['rule_id'] for item in rbac_findings(roles, bindings)}
    assert rules == {
        'kubernetes.rbac.bound-wildcard-clusterrole',
        'kubernetes.rbac.default-service-account-cluster-admin',
    }


def test_summary_proves_read_only_paths_and_coverage():
    payload = analyze_resources(
        server='https://127.0.0.1:6443',
        version={'gitVersion': 'v1.35.0'},
        namespaces=[],
        pods=[],
        deployments=[],
        roles=[],
        bindings=[],
        coverage=[
            {
                'path': '/version', 'status': 200, 'accessible': True,
                'truncated': False, 'resolved_ip': '127.0.0.1',
            },
            {
                'path': '/apis/rbac.authorization.k8s.io/v1/clusterroles',
                'status': 403, 'accessible': False, 'truncated': False,
                'resolved_ip': '127.0.0.1',
            },
        ],
    )
    summary = payload['observations'][0]
    assert summary['read_only'] is True
    assert summary['secrets_endpoint_requested'] is False
    assert summary['coverage_gaps'] == 1
    assert summary['dns_pinned_for_scan'] is True
    assert summary['pinned_destination_ips'] == ['127.0.0.1']
    assert all('/secrets' not in path for path in summary['requested_paths'])


def test_cluster_collection_reuses_one_pinned_destination(monkeypatch):
    destination = PinnedHTTPDestination(
        scheme='https', host='kube.example.test', port=6443, resolved_ips=('192.0.2.44',)
    )
    transport = KubernetesTransport(
        server='https://kube.example.test:6443',
        destination=destination,
        ssl_context=object(),
        headers={'Authorization': 'Bearer redacted-fixture'},
        cleanup_paths=(),
    )
    seen_destinations = []
    seen_urls = []

    monkeypatch.setattr(kubernetes_security, 'load_kubeconfig', lambda *_args: transport)

    def fake_request(method, url, **kwargs):
        assert method == 'GET'
        seen_destinations.append(kwargs['destination'])
        seen_urls.append(url)
        body = b'{"gitVersion":"v1.35.0"}' if url.endswith('/version') else b'{"items":[]}'
        return PinnedHTTPResponse(
            status=200,
            headers={'content-type': 'application/json'},
            body=body,
            url=url,
            resolved_ip='192.0.2.44',
        )

    monkeypatch.setattr(kubernetes_security, 'request_pinned', fake_request)
    result = kubernetes_security.analyze_cluster(
        'https://kube.example.test:6443', '/unused-kubeconfig'
    )

    assert len(seen_urls) == 6
    assert all(item is destination for item in seen_destinations)
    assert all('/secrets' not in url for url in seen_urls)
    summary = result['observations'][0]
    assert summary['dns_pinned_for_scan'] is True
    assert summary['pinned_destination_ips'] == ['192.0.2.44']


def test_operation_scope_prevents_second_dns_resolution(monkeypatch):
    authorization_calls: list[bool] = []
    connects: list[tuple] = []

    class FakeSocket:
        def settimeout(self, _timeout):
            return None

        def connect(self, address):
            connects.append(address)

        def close(self):
            return None

    class FakeResponse:
        status = 200

        def getheader(self, _name):
            return None

        def read(self, _size):
            return b'{}'

        def getheaders(self):
            return [('Content-Type', 'application/json')]

    class FakeConnection:
        def __init__(self, _host, _port, timeout=None):
            self.sock = None
            self.timeout = timeout

        def request(self, _method, _path, headers=None):
            assert headers is not None

        def getresponse(self):
            return FakeResponse()

        def close(self):
            return None

    def authorize(_target, *, url=False, resolve_dns=False):
        assert url is True
        authorization_calls.append(resolve_dns)
        if resolve_dns:
            if authorization_calls.count(True) > 1:
                raise AssertionError('DNS was resolved more than once for the pinned operation')
            return ('192.0.2.40',)
        return ()

    monkeypatch.setattr(pinned_http, 'require_authorized_target', authorize)
    monkeypatch.setattr(pinned_http.http.client, 'HTTPConnection', FakeConnection)
    monkeypatch.setattr(pinned_http.socket, 'socket', lambda *_args, **_kwargs: FakeSocket())

    base = 'http://cluster.example.test:8080'
    with pinned_http.pinned_http_operation(base):
        first = pinned_http.request_pinned('GET', f'{base}/version')
        second = pinned_http.request_pinned('GET', f'{base}/api/v1/pods?limit=1000')

    assert first.resolved_ip == second.resolved_ip == '192.0.2.40'
    assert authorization_calls == [True, False, False]
    assert connects == [('192.0.2.40', 8080), ('192.0.2.40', 8080)]


def _kubeconfig(server: str, *, user: dict | None = None, cluster_extra: dict | None = None) -> str:
    cluster = {
        'server': server,
        'certificate-authority-data': base64.b64encode(b'not-a-real-ca-for-parser-only').decode(),
        **(cluster_extra or {}),
    }
    document = {
        'apiVersion': 'v1',
        'kind': 'Config',
        'current-context': 'ctx',
        'clusters': [{'name': 'cluster', 'cluster': cluster}],
        'contexts': [{'name': 'ctx', 'context': {'cluster': 'cluster', 'user': 'scanner'}}],
        'users': [{'name': 'scanner', 'user': user or {'token': 'fixture-token'}}],
    }
    return yaml.safe_dump(document)


def test_kubeconfig_target_mismatch_and_exec_auth_fail_closed(tmp_path):
    mismatch = tmp_path / 'mismatch.yaml'
    mismatch.write_text(_kubeconfig('https://other.example.test:6443'), encoding='utf-8')
    with pytest.raises(KubernetesSecurityError, match='does not match'):
        load_kubeconfig(str(mismatch), 'https://kube.example.test:6443')

    executable = tmp_path / 'exec.yaml'
    executable.write_text(
        _kubeconfig(
            'https://kube.example.test:6443',
            user={'exec': {'command': '/bin/sh', 'args': ['-c', 'echo forbidden']}},
        ),
        encoding='utf-8',
    )
    with pytest.raises(KubernetesSecurityError, match='executable'):
        load_kubeconfig(str(executable), 'https://kube.example.test:6443')

    insecure = tmp_path / 'insecure.yaml'
    insecure.write_text(
        _kubeconfig(
            'https://kube.example.test:6443',
            cluster_extra={'insecure-skip-tls-verify': True},
        ),
        encoding='utf-8',
    )
    with pytest.raises(KubernetesSecurityError, match='insecure-skip-tls-verify'):
        load_kubeconfig(str(insecure), 'https://kube.example.test:6443')
