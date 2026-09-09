from __future__ import annotations

import base64

import pytest
import yaml

from fastapi_app.services.kubernetes_security import (
    KubernetesSecurityError,
    analyze_resources,
    canonical_server,
    load_kubeconfig,
    rbac_findings,
    workload_findings,
)


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
            {'path': '/version', 'status': 200, 'accessible': True, 'truncated': False},
            {'path': '/apis/rbac.authorization.k8s.io/v1/clusterroles', 'status': 403, 'accessible': False, 'truncated': False},
        ],
    )
    summary = payload['observations'][0]
    assert summary['read_only'] is True
    assert summary['secrets_endpoint_requested'] is False
    assert summary['coverage_gaps'] == 1
    assert all('/secrets' not in path for path in summary['requested_paths'])


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
