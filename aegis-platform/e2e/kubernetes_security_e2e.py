#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import django
import yaml

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
django.setup()

from django.contrib.auth import get_user_model

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import create_credential_secret
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.capability_registry import get_capability, validate_capability_options
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution
from fastapi_app.tasks.native_capabilities import run_native_capability_scan


def require_env(name: str) -> str:
    value = os.getenv(name, '').strip()
    if not value:
        raise RuntimeError(f'{name} is required')
    return value


def assert_secret_absent(secret: str, *payloads) -> None:
    if not secret:
        raise AssertionError('secret redaction proof requires non-empty secret material')
    for payload in payloads:
        rendered = payload if isinstance(payload, str) else json.dumps(payload, default=str, sort_keys=True)
        if secret in rendered:
            raise AssertionError('kubeconfig secret material leaked into durable non-secret payload')


def main() -> int:
    target = require_env('AEGIS_KUBE_TARGET')
    kubeconfig_path = Path(require_env('AEGIS_KUBECONFIG_FILE'))
    kubeconfig = kubeconfig_path.read_text(encoding='utf-8')
    if not kubeconfig.strip():
        raise RuntimeError('kubeconfig fixture is empty')
    kubeconfig_doc = yaml.safe_load(kubeconfig)
    token = str(kubeconfig_doc['users'][0]['user']['token'])
    if not token:
        raise RuntimeError('kubeconfig fixture token is empty')

    User = get_user_model()
    user = User.objects.create_user(email='kubernetes-e2e@example.test', password='Kubernetes-E2E-123!')
    project = Project.objects.create(name='Kubernetes E2E', slug='kubernetes-e2e', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='Kind Cluster',
        slug='kind-cluster',
        type=Asset.Type.KUBERNETES,
        owner=user,
        configuration={'url': target},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=target,
        reason='Disposable kind cluster authorized for Kubernetes reality CI',
    )
    credential = create_credential_secret(
        project=project,
        actor=user,
        name='kind-readonly-kubeconfig',
        kind=CredentialSecret.Kind.KUBECONFIG,
        secret=kubeconfig,
        scope={'api_server': target, 'access': 'read-only-posture'},
    )
    capability = get_capability('kubernetes.read-only-posture')
    if not capability.credential_required or capability.credential_kinds != ('kubeconfig',):
        raise AssertionError('Kubernetes capability credential contract is not active')
    options = validate_capability_options(capability, {})
    credential_context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=user.id,
        refs=[str(credential.id)],
        capability_id=capability.id,
        allowed_kinds=capability.credential_kinds,
        purpose='kubernetes-e2e:schedule',
        target=target,
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        authorization_decision=authorization,
        name='Kubernetes read-only posture E2E',
        scan_type=Scan.Type.URL,
        engines=[capability.tool],
        config={
            'target': target,
            'capability_options': options,
            'credential_refs': [str(credential.id)],
            'credential_context': credential_context,
            'capability_id': capability.id,
            'capability_category': capability.category,
            'capability_risk': capability.risk,
            'capability_policy_version': 'capability-execution.v3',
            'capability_source': capability.source,
            'capability_adapter': capability.adapter,
            'credential_mode': capability.credential_mode,
            'credential_required': capability.credential_required,
        },
        initiated_by=user,
        status=Scan.Status.QUEUED,
    )

    assert_secret_absent(kubeconfig, scan.config)
    assert_secret_absent(token, scan.config)

    async_result = run_native_capability_scan.delay(str(scan.id))
    result = async_result.get(timeout=240, disable_sync_subtasks=False)
    if result.get('status') != Scan.Status.COMPLETED:
        raise AssertionError(f'Kubernetes scan did not complete: {result!r}')

    scan.refresh_from_db()
    if scan.status != Scan.Status.COMPLETED:
        raise AssertionError(f'Persisted scan status is {scan.status}')
    execution = ScanEngineExecution.objects.get(scan=scan)
    if execution.status != ScanEngineExecution.ExecutionStatus.COMPLETED:
        raise AssertionError(f'Engine execution status is {execution.status}')

    scanner_evidence = Evidence.objects.get(scan=scan, evidence_type='scanner_output')
    normalized = scanner_evidence.metadata.get('normalized') or {}
    observations = normalized.get('observations') or []
    summary = next((item for item in observations if item.get('kind') == 'kubernetes-security-summary'), None)
    if not summary:
        raise AssertionError('Kubernetes summary observation is missing')
    if summary.get('read_only') is not True or summary.get('secrets_endpoint_requested') is not False:
        raise AssertionError(f'Read-only proof is invalid: {summary!r}')
    if summary.get('dns_pinned_for_scan') is not True:
        raise AssertionError(f'Kubernetes scan-wide DNS pin proof is missing: {summary!r}')
    pinned_ips = [str(value) for value in summary.get('pinned_destination_ips', [])]
    if not pinned_ips:
        raise AssertionError(f'Kubernetes pinned destination IP evidence is missing: {summary!r}')
    coverage_ips = {
        str(item.get('resolved_ip'))
        for item in summary.get('coverage', [])
        if isinstance(item, dict) and item.get('resolved_ip')
    }
    if not coverage_ips or not coverage_ips.issubset(set(pinned_ips)):
        raise AssertionError(
            f'Kubernetes request coverage escaped the pinned destination set: coverage={coverage_ips} pinned={pinned_ips}'
        )
    if any('/secrets' in str(path) for path in summary.get('requested_paths', [])):
        raise AssertionError('Kubernetes analyzer requested a secrets API path')

    findings = list(Vulnerability.objects.filter(scan=scan).order_by('id'))
    rules = {str(item.raw_data.get('rule_id') or '') for item in findings}
    expected = {
        'kubernetes.workload.privileged-container',
        'kubernetes.rbac.bound-wildcard-clusterrole',
        'kubernetes.rbac.default-service-account-cluster-admin',
    }
    missing = expected - rules
    if missing:
        raise AssertionError(f'Expected Kubernetes findings are missing: {sorted(missing)}; observed={sorted(rules)}')
    finding_evidence_count = Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count()
    if finding_evidence_count != len(findings):
        raise AssertionError('Every semantic Kubernetes finding must have linked evidence')

    if not CredentialAccess.objects.filter(
        credential=credential,
        operation=CredentialAccess.Operation.RESOLVE_INTERNAL,
        result=CredentialAccess.Result.SUCCESS,
    ).exists():
        raise AssertionError('Worker credential resolution was not recorded in the append-only vault ledger')

    durable_payloads = (
        scanner_evidence.raw_output,
        scanner_evidence.metadata,
        execution.result_data,
        scan.config,
        scan.engine_results,
        result,
        [item.raw_data for item in findings],
        list(Evidence.objects.filter(scan=scan).values('raw_output', 'metadata')),
    )
    assert_secret_absent(kubeconfig, *durable_payloads)
    assert_secret_absent(token, *durable_payloads)

    before = {
        'findings': Vulnerability.objects.filter(scan=scan).count(),
        'evidence': Evidence.objects.filter(scan=scan).count(),
        'executions': ScanEngineExecution.objects.filter(scan=scan).count(),
    }
    redelivery = run_native_capability_scan.delay(str(scan.id)).get(timeout=60, disable_sync_subtasks=False)
    after = {
        'findings': Vulnerability.objects.filter(scan=scan).count(),
        'evidence': Evidence.objects.filter(scan=scan).count(),
        'executions': ScanEngineExecution.objects.filter(scan=scan).count(),
    }
    if before != after:
        raise AssertionError(f'Redelivery duplicated durable records: before={before}, after={after}')
    if redelivery.get('scan_id') != str(scan.id):
        raise AssertionError(f'Redelivery returned unexpected scan identity: {redelivery!r}')
    assert_secret_absent(kubeconfig, redelivery)
    assert_secret_absent(token, redelivery)

    print(json.dumps({
        'status': 'ok',
        'scan_id': str(scan.id),
        'engine': capability.tool,
        'finding_count': len(findings),
        'evidence_count': after['evidence'],
        'credential_access_count': CredentialAccess.objects.filter(credential=credential).count(),
        'read_only': summary['read_only'],
        'secrets_endpoint_requested': summary['secrets_endpoint_requested'],
        'dns_pinned_for_scan': summary['dns_pinned_for_scan'],
        'pinned_destination_ips': pinned_ips,
        'coverage_gaps': summary.get('coverage_gaps', 0),
        'rules': sorted(rules),
    }, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
