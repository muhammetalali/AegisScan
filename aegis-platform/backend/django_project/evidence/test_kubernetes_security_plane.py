from __future__ import annotations

import json

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.credential_execution import (
    authorize_credential_refs_for_execution,
    resolve_credential_refs_for_worker,
)
from fastapi_app.services.native_finding_projection import project_native_findings, sync_scan_finding_counts


@pytest.mark.django_db
def test_kubeconfig_scope_is_enforced_before_worker_secret_resolution():
    user = get_user_model().objects.create_user(email='kube-scope@example.test', password='KubeScope-123!')
    project = Project.objects.create(name='Kubernetes Scope', slug='kubernetes-scope', owner=user)
    target = 'https://127.0.0.1:6443'
    secret = 'apiVersion: v1\nkind: Config\ncurrent-context: fixture\n'
    credential = create_credential_secret(
        project=project,
        actor=user,
        name='cluster-readonly',
        kind=CredentialSecret.Kind.KUBECONFIG,
        secret=secret,
        scope={'api_server': target},
    )

    context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=user.id,
        refs=[str(credential.id)],
        capability_id='kubernetes.read-only-posture',
        allowed_kinds=('kubeconfig',),
        target=target,
    )
    assert context['credential_refs'][0]['kind'] == 'kubeconfig'
    materials, worker_context = resolve_credential_refs_for_worker(
        project_id=project.id,
        actor_id=user.id,
        refs=[str(credential.id)],
        capability_id='kubernetes.read-only-posture',
        allowed_kinds=('kubeconfig',),
        target=target,
    )
    assert materials[0]['secret'] == secret
    assert worker_context['credential_material_handling'] == 'worker-resolved-redacted'
    assert secret not in json.dumps(worker_context, sort_keys=True)

    with pytest.raises(CredentialVaultDenied, match='not scoped'):
        authorize_credential_refs_for_execution(
            project_id=project.id,
            actor_id=user.id,
            refs=[str(credential.id)],
            capability_id='kubernetes.read-only-posture',
            allowed_kinds=('kubeconfig',),
            target='https://127.0.0.1:7443',
        )
    denied = CredentialAccess.objects.filter(
        credential=credential,
        operation=CredentialAccess.Operation.AUTHORIZE_USE,
        result=CredentialAccess.Result.DENIED,
    ).latest('created_at')
    assert denied.metadata['scope_matches_target'] is False
    assert secret not in json.dumps(denied.metadata, sort_keys=True)


@pytest.mark.django_db
def test_kubernetes_findings_and_evidence_are_location_stable_and_idempotent():
    user = get_user_model().objects.create_user(email='kube-findings@example.test', password='KubeFindings-123!')
    project = Project.objects.create(name='Kubernetes Findings', slug='kubernetes-findings', owner=user)
    target = 'https://127.0.0.1:6443'
    asset = Asset.objects.create(
        project=project,
        name='Authorized Cluster',
        slug='authorized-cluster',
        type=Asset.Type.KUBERNETES,
        owner=user,
        configuration={'url': target},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=target,
        reason='CI authorized cluster fixture',
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        authorization_decision=authorization,
        name='Kubernetes posture',
        scan_type=Scan.Type.URL,
        engines=['aegis-kubernetes-security'],
        initiated_by=user,
    )
    normalized = {
        'schema': 'aegis.native-observations.v1',
        'count': 2,
        'observations': [
            {
                'kind': 'kubernetes-security-finding',
                'rule_id': 'kubernetes.workload.privileged-container',
                'title': 'Privileged container A',
                'description': 'Container a is privileged.',
                'severity': 'high',
                'confidence': 'high',
                'remediation': 'Disable privileged mode.',
                'namespace': 'payments',
                'resource_kind': 'Pod',
                'resource_name': 'pod-a',
                'container': 'a',
                'location': 'payments/Pod/pod-a/a',
                'cwe_id': 'CWE-250',
            },
            {
                'kind': 'kubernetes-security-finding',
                'rule_id': 'kubernetes.workload.privileged-container',
                'title': 'Privileged container B',
                'description': 'Container b is privileged.',
                'severity': 'high',
                'confidence': 'high',
                'remediation': 'Disable privileged mode.',
                'namespace': 'payments',
                'resource_kind': 'Pod',
                'resource_name': 'pod-b',
                'container': 'b',
                'location': 'payments/Pod/pod-b/b',
                'cwe_id': 'CWE-250',
            },
        ],
    }

    first_findings, first_evidence = project_native_findings(
        scan=scan,
        capability_id='kubernetes.read-only-posture',
        source_engine='aegis-kubernetes-security',
        target=target,
        normalized=normalized,
    )
    assert len(first_findings) == 2
    assert len(set(first_findings)) == 2
    assert len(first_evidence) == 2

    second_findings, second_evidence = project_native_findings(
        scan=scan,
        capability_id='kubernetes.read-only-posture',
        source_engine='aegis-kubernetes-security',
        target=target,
        normalized=normalized,
    )
    assert second_findings == first_findings
    assert second_evidence == first_evidence
    assert Vulnerability.objects.filter(scan=scan, category='kubernetes-security').count() == 2
    assert Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count() == 2

    sync_scan_finding_counts(scan)
    scan.save(update_fields=['findings_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count'])
    scan.refresh_from_db()
    assert scan.findings_count == 2
    assert scan.high_count == 2
    for finding in Vulnerability.objects.filter(scan=scan):
        assert finding.raw_data['capability_id'] == 'kubernetes.read-only-posture'
        assert finding.raw_data['namespace'] == 'payments'
        assert finding.raw_data['location'].startswith('payments/Pod/')
