#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests
import yaml

SCHEMA = 'aegis.kubernetes-security.v1'
REQUEST_TIMEOUT = (5, 20)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 1000


class KubernetesSecurityError(RuntimeError):
    pass


def _canonical_server(value: str) -> str:
    parsed = urlsplit(str(value or '').strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme != 'https' or not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise KubernetesSecurityError('Kubernetes API server must be an absolute HTTPS URL without credentials, query, or fragment')
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise KubernetesSecurityError('Kubernetes API server contains an invalid port') from exc
    authority = host if port == 443 else f'{host}:{port}'
    path = parsed.path.rstrip('/')
    return urlunsplit(('https', authority, path, '', ''))


def _named(entries: Any, name: str, kind: str) -> dict[str, Any]:
    if not isinstance(entries, list):
        raise KubernetesSecurityError(f'kubeconfig {kind} list is invalid')
    for item in entries:
        if isinstance(item, dict) and item.get('name') == name and isinstance(item.get(kind), dict):
            return item[kind]
    raise KubernetesSecurityError(f'kubeconfig {kind} {name!r} was not found')


def _decode_embedded(value: Any, label: str, limit: int = 1024 * 1024) -> bytes:
    text = str(value or '').strip()
    if not text:
        raise KubernetesSecurityError(f'kubeconfig {label} is missing')
    try:
        decoded = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KubernetesSecurityError(f'kubeconfig {label} is not valid base64') from exc
    if not decoded or len(decoded) > limit:
        raise KubernetesSecurityError(f'kubeconfig {label} exceeds the allowed size')
    return decoded


def _temp_file(data: bytes, suffix: str, cleanup: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix='aegis-kube-', suffix=suffix)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)
    cleanup.append(path)
    return path


def _load_kubeconfig(path: str, authorized_target: str) -> tuple[requests.Session, str, list[str]]:
    candidate = Path(path)
    try:
        if not candidate.is_file() or candidate.stat().st_size > 262144:
            raise KubernetesSecurityError('kubeconfig must be a regular file no larger than 256 KiB')
        document = yaml.safe_load(candidate.read_text(encoding='utf-8'))
    except UnicodeDecodeError as exc:
        raise KubernetesSecurityError('kubeconfig must be UTF-8 YAML') from exc
    except yaml.YAMLError as exc:
        raise KubernetesSecurityError('kubeconfig is not valid YAML') from exc
    if not isinstance(document, dict):
        raise KubernetesSecurityError('kubeconfig root must be an object')

    context_name = str(document.get('current-context') or '').strip()
    if not context_name:
        raise KubernetesSecurityError('kubeconfig current-context is required')
    context = _named(document.get('contexts'), context_name, 'context')
    cluster_name = str(context.get('cluster') or '').strip()
    user_name = str(context.get('user') or '').strip()
    if not cluster_name or not user_name:
        raise KubernetesSecurityError('kubeconfig current context must bind a cluster and user')
    cluster = _named(document.get('clusters'), cluster_name, 'cluster')
    user = _named(document.get('users'), user_name, 'user')

    server = _canonical_server(str(cluster.get('server') or ''))
    if server != _canonical_server(authorized_target):
        raise KubernetesSecurityError('kubeconfig API server does not match the authorized asset target')
    if cluster.get('insecure-skip-tls-verify') is True:
        raise KubernetesSecurityError('kubeconfig insecure-skip-tls-verify is forbidden')
    if 'certificate-authority' in cluster:
        raise KubernetesSecurityError('external certificate-authority paths are forbidden; embed certificate-authority-data')

    forbidden_user_fields = {'exec', 'auth-provider', 'tokenFile', 'client-certificate', 'client-key', 'username', 'password'}
    present_forbidden = sorted(field for field in forbidden_user_fields if user.get(field) not in (None, '', {}))
    if present_forbidden:
        raise KubernetesSecurityError(f'kubeconfig user contains unsupported external or executable authentication fields: {present_forbidden}')

    cleanup: list[str] = []
    try:
        ca_path = _temp_file(_decode_embedded(cluster.get('certificate-authority-data'), 'certificate-authority-data'), '.ca.crt', cleanup)
        token = str(user.get('token') or '').strip()
        client_cert_data = user.get('client-certificate-data')
        client_key_data = user.get('client-key-data')
        has_client_pair = bool(client_cert_data) or bool(client_key_data)
        if token and has_client_pair:
            raise KubernetesSecurityError('kubeconfig must use one authentication mechanism: token or embedded client certificate')
        if not token and not has_client_pair:
            raise KubernetesSecurityError('kubeconfig must contain a token or embedded client certificate credentials')
        if token and (len(token) > 16384 or any(ch in token for ch in '\r\n\x00')):
            raise KubernetesSecurityError('kubeconfig token is invalid')

        session = requests.Session()
        session.trust_env = False
        session.verify = ca_path
        session.headers.update({'Accept': 'application/json', 'User-Agent': 'AegisScan-KubernetesSecurity/1.0'})
        if token:
            session.headers['Authorization'] = f'Bearer {token}'
        else:
            cert_path = _temp_file(_decode_embedded(client_cert_data, 'client-certificate-data'), '.client.crt', cleanup)
            key_path = _temp_file(_decode_embedded(client_key_data, 'client-key-data'), '.client.key', cleanup)
            session.cert = (cert_path, key_path)
        return session, server, cleanup
    except BaseException:
        for item in cleanup:
            Path(item).unlink(missing_ok=True)
        raise


def _bounded_json(response: requests.Response) -> dict[str, Any]:
    if response.is_redirect:
        raise KubernetesSecurityError('Kubernetes API redirects are not allowed')
    if response.status_code != 200:
        raise KubernetesSecurityError(f'Kubernetes API read failed with HTTP {response.status_code} for {urlsplit(response.url).path}')
    length = response.headers.get('Content-Length')
    if length:
        try:
            if int(length) > MAX_RESPONSE_BYTES:
                raise KubernetesSecurityError('Kubernetes API response exceeds the allowed size')
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=65536):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise KubernetesSecurityError('Kubernetes API response exceeds the allowed size')
        chunks.append(chunk)
    try:
        value = json.loads(b''.join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KubernetesSecurityError('Kubernetes API returned invalid JSON') from exc
    if not isinstance(value, dict):
        raise KubernetesSecurityError('Kubernetes API response root must be an object')
    return value


def _get(session: requests.Session, server: str, path: str, *, list_request: bool = False) -> dict[str, Any]:
    url = f'{server}{path}'
    params = {'limit': str(MAX_ITEMS)} if list_request else None
    with session.get(url, params=params, timeout=REQUEST_TIMEOUT, allow_redirects=False, stream=True) as response:
        return _bounded_json(response)


def _items(value: dict[str, Any]) -> list[dict[str, Any]]:
    items = value.get('items')
    if not isinstance(items, list):
        return []
    return [item for item in items[:MAX_ITEMS] if isinstance(item, dict)]


def _finding(rule_id: str, title: str, severity: str, description: str, remediation: str, *, namespace: str = '', resource_kind: str = '', resource_name: str = '', container: str = '', confidence: str = 'high', cwe_id: str = '', owasp_category: str = '') -> dict[str, Any]:
    location = '/'.join(part for part in (namespace or '_cluster', resource_kind, resource_name, container) if part)
    return {
        'kind': 'kubernetes-security-finding',
        'rule_id': rule_id,
        'title': title,
        'severity': severity,
        'confidence': confidence,
        'category': 'kubernetes-security',
        'description': description,
        'remediation': remediation,
        'namespace': namespace[:253],
        'resource_kind': resource_kind[:100],
        'resource_name': resource_name[:253],
        'container': container[:253],
        'location': location[:2048],
        'cwe_id': cwe_id,
        'owasp_category': owasp_category,
    }


def _workload_findings(kind: str, resource: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = resource.get('metadata') if isinstance(resource.get('metadata'), dict) else {}
    namespace = str(metadata.get('namespace') or 'default')
    name = str(metadata.get('name') or '')
    spec = resource.get('spec') if isinstance(resource.get('spec'), dict) else {}
    if kind == 'Deployment':
        template = spec.get('template') if isinstance(spec.get('template'), dict) else {}
        spec = template.get('spec') if isinstance(template.get('spec'), dict) else {}
    findings: list[dict[str, Any]] = []

    for field, label in (('hostNetwork', 'network'), ('hostPID', 'PID'), ('hostIPC', 'IPC')):
        if spec.get(field) is True:
            findings.append(_finding(
                f'kubernetes.workload.{field.lower()}',
                f'Workload shares the host {label} namespace',
                'high' if field in {'hostPID', 'hostIPC'} else 'medium',
                f'{kind} {namespace}/{name} explicitly enables {field}, weakening workload isolation from the node.',
                f'Disable {field} unless the workload has a narrowly documented platform requirement.',
                namespace=namespace, resource_kind=kind, resource_name=name,
                cwe_id='CWE-250', owasp_category='Kubernetes Security - Workload Isolation',
            ))

    volumes = spec.get('volumes') if isinstance(spec.get('volumes'), list) else []
    for volume in volumes[:200]:
        if isinstance(volume, dict) and isinstance(volume.get('hostPath'), dict):
            volume_name = str(volume.get('name') or 'hostPath')
            findings.append(_finding(
                'kubernetes.workload.hostpath-volume',
                'Workload mounts a hostPath volume',
                'medium',
                f'{kind} {namespace}/{name} mounts host filesystem content through hostPath volume {volume_name!r}.',
                'Replace hostPath with a scoped volume source where possible; otherwise restrict the path and mount read-only.',
                namespace=namespace, resource_kind=kind, resource_name=name,
                cwe_id='CWE-732', owasp_category='Kubernetes Security - Workload Isolation',
            ))

    containers = []
    for key in ('initContainers', 'containers', 'ephemeralContainers'):
        value = spec.get(key)
        if isinstance(value, list):
            containers.extend(item for item in value[:500] if isinstance(item, dict))
    pod_security = spec.get('securityContext') if isinstance(spec.get('securityContext'), dict) else {}
    for container_obj in containers[:1000]:
        container_name = str(container_obj.get('name') or '')
        security = container_obj.get('securityContext') if isinstance(container_obj.get('securityContext'), dict) else {}
        if security.get('privileged') is True:
            findings.append(_finding(
                'kubernetes.workload.privileged-container', 'Privileged container is enabled', 'high',
                f'Container {container_name!r} in {kind} {namespace}/{name} explicitly runs privileged and can bypass normal container isolation.',
                'Set securityContext.privileged=false and grant only the minimum Linux capabilities required.',
                namespace=namespace, resource_kind=kind, resource_name=name, container=container_name,
                cwe_id='CWE-250', owasp_category='Kubernetes Security - Privilege Escalation',
            ))
        if security.get('allowPrivilegeEscalation') is True:
            findings.append(_finding(
                'kubernetes.workload.allow-privilege-escalation', 'Container explicitly allows privilege escalation', 'medium',
                f'Container {container_name!r} in {kind} {namespace}/{name} explicitly sets allowPrivilegeEscalation=true.',
                'Set securityContext.allowPrivilegeEscalation=false unless a documented workload requirement prevents it.',
                namespace=namespace, resource_kind=kind, resource_name=name, container=container_name,
                cwe_id='CWE-250', owasp_category='Kubernetes Security - Privilege Escalation',
            ))
        capabilities = security.get('capabilities') if isinstance(security.get('capabilities'), dict) else {}
        added = capabilities.get('add') if isinstance(capabilities.get('add'), list) else []
        if any(str(value).upper() == 'ALL' for value in added):
            findings.append(_finding(
                'kubernetes.workload.capabilities-all', 'Container requests all Linux capabilities', 'high',
                f'Container {container_name!r} in {kind} {namespace}/{name} explicitly adds the ALL Linux capability set.',
                'Drop ALL capabilities and add back only individually justified capabilities.',
                namespace=namespace, resource_kind=kind, resource_name=name, container=container_name,
                cwe_id='CWE-250', owasp_category='Kubernetes Security - Privilege Escalation',
            ))
        run_as_user = security.get('runAsUser', pod_security.get('runAsUser'))
        if run_as_user == 0:
            findings.append(_finding(
                'kubernetes.workload.explicit-root', 'Container is explicitly configured to run as UID 0', 'medium',
                f'Container {container_name!r} in {kind} {namespace}/{name} explicitly sets runAsUser=0.',
                'Run the workload as a non-root UID and set runAsNonRoot=true where compatible.',
                namespace=namespace, resource_kind=kind, resource_name=name, container=container_name,
                cwe_id='CWE-250', owasp_category='Kubernetes Security - Privilege Escalation',
            ))
    return findings


def _role_is_wildcard(role: dict[str, Any]) -> bool:
    rules = role.get('rules') if isinstance(role.get('rules'), list) else []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = {str(value) for value in rule.get('verbs', []) if isinstance(value, str)} if isinstance(rule.get('verbs'), list) else set()
        resources = {str(value) for value in rule.get('resources', []) if isinstance(value, str)} if isinstance(rule.get('resources'), list) else set()
        if '*' in verbs and '*' in resources:
            return True
    return False


def _rbac_findings(roles: list[dict[str, Any]], bindings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dangerous: set[str] = set()
    for role in roles:
        metadata = role.get('metadata') if isinstance(role.get('metadata'), dict) else {}
        name = str(metadata.get('name') or '')
        if name and _role_is_wildcard(role):
            dangerous.add(name)
    findings: list[dict[str, Any]] = []
    for binding in bindings:
        metadata = binding.get('metadata') if isinstance(binding.get('metadata'), dict) else {}
        name = str(metadata.get('name') or '')
        role_ref = binding.get('roleRef') if isinstance(binding.get('roleRef'), dict) else {}
        role_name = str(role_ref.get('name') or '')
        subjects = binding.get('subjects') if isinstance(binding.get('subjects'), list) else []
        if role_name in dangerous:
            findings.append(_finding(
                'kubernetes.rbac.bound-wildcard-clusterrole', 'Bound ClusterRole grants wildcard resource and verb access', 'high',
                f'ClusterRoleBinding {name!r} binds wildcard ClusterRole {role_name!r}, producing a broad cluster-wide authorization grant.',
                'Replace wildcard verbs/resources with the minimum explicit RBAC permissions required by the bound subjects.',
                resource_kind='ClusterRoleBinding', resource_name=name,
                cwe_id='CWE-732', owasp_category='Kubernetes Security - Excessive RBAC',
            ))
        if role_name == 'cluster-admin':
            for subject in subjects[:500]:
                if not isinstance(subject, dict):
                    continue
                if str(subject.get('kind') or '') == 'ServiceAccount' and str(subject.get('name') or '') == 'default':
                    subject_namespace = str(subject.get('namespace') or 'default')
                    findings.append(_finding(
                        'kubernetes.rbac.default-service-account-cluster-admin', 'Default ServiceAccount is bound to cluster-admin', 'critical',
                        f'ClusterRoleBinding {name!r} grants cluster-admin to the default ServiceAccount in namespace {subject_namespace!r}.',
                        'Remove the cluster-admin binding and create a dedicated ServiceAccount with narrowly scoped RBAC permissions.',
                        namespace=subject_namespace, resource_kind='ClusterRoleBinding', resource_name=name,
                        cwe_id='CWE-732', owasp_category='Kubernetes Security - Excessive RBAC',
                    ))
    return findings


def analyze_cluster(target: str, kubeconfig_path: str) -> dict[str, Any]:
    session, server, cleanup = _load_kubeconfig(kubeconfig_path, target)
    try:
        version = _get(session, server, '/version')
        namespaces = _items(_get(session, server, '/api/v1/namespaces', list_request=True))
        pods = _items(_get(session, server, '/api/v1/pods', list_request=True))
        deployments = _items(_get(session, server, '/apis/apps/v1/deployments', list_request=True))
        roles = _items(_get(session, server, '/apis/rbac.authorization.k8s.io/v1/clusterroles', list_request=True))
        bindings = _items(_get(session, server, '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings', list_request=True))

        findings: list[dict[str, Any]] = []
        for pod in pods:
            findings.extend(_workload_findings('Pod', pod))
        for deployment in deployments:
            findings.extend(_workload_findings('Deployment', deployment))
        findings.extend(_rbac_findings(roles, bindings))

        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in findings:
            unique[(str(finding.get('rule_id') or ''), str(finding.get('location') or ''))] = finding
        bounded = list(unique.values())[:2000]
        summary = {
            'kind': 'kubernetes-security-summary',
            'server': server,
            'git_version': str(version.get('gitVersion') or '')[:100],
            'namespace_count': len(namespaces),
            'pod_count': len(pods),
            'deployment_count': len(deployments),
            'clusterrole_count': len(roles),
            'clusterrolebinding_count': len(bindings),
            'finding_count': len(bounded),
            'read_only': True,
            'secrets_endpoint_requested': False,
        }
        return {
            'schema': SCHEMA,
            'target': server,
            'finding_count': len(bounded),
            'observations': [summary, *bounded],
        }
    finally:
        session.close()
        for item in cleanup:
            Path(item).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AegisScan read-only Kubernetes security posture analyzer')
    parser.add_argument('target')
    parser.add_argument('--kubeconfig', required=True)
    args = parser.parse_args(argv)
    try:
        result = analyze_cluster(args.target, args.kubeconfig)
    except (KubernetesSecurityError, requests.RequestException, OSError, ValueError) as exc:
        print(json.dumps({'schema': SCHEMA, 'error': str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
