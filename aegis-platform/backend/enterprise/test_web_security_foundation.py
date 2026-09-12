from __future__ import annotations

import uuid

import pytest
from django.core.exceptions import ValidationError

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.models import (
    AuthorizationPolicyManifest,
    ProviderApprovalRecord,
    SecurityGraphEdge,
    SecurityGraphNode,
    WebSecurityObservation,
    WebSecurityValidationRun,
)
from fastapi_app.services.web_security_foundation import (
    persist_policy,
    persist_provider_approval,
    run_authorization_matrix,
    upsert_graph_snapshot,
)


def _fixture():
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f'web-domain-{suffix}@example.com',
        password='Aegis-Domain-Test-Password!42',
        first_name='Domain',
        last_name='Fixture',
    )
    project = Project.objects.create(
        name=f'Web Domain {suffix}',
        slug=f'web-domain-{suffix}',
        owner=user,
    )
    return user, project


@pytest.mark.django_db
def test_policy_and_provider_approval_are_immutable_append_only_records():
    user, project = _fixture()
    policy, _ = persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': '*',
        'endpoint': '/api/orders/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'order',
        'allowed': True,
        'ownership_rule': 'owner_only',
        'tenant_rule': 'same_tenant',
        'sensitive_operation': False,
        'required_scopes': [],
        'conditions': {},
        'policy_source': 'operator_declared',
        'provenance': {'ticket': 'SEC-1'},
        'confidence': 1.0,
        'version': 1,
    })
    policy.allowed = False
    with pytest.raises(ValidationError, match='immutable'):
        policy.save()
    with pytest.raises(RuntimeError, match='immutable'):
        AuthorizationPolicyManifest.objects.filter(pk=policy.pk).update(allowed=False)
    with pytest.raises(ValidationError, match='immutable'):
        policy.delete()

    provider, _ = persist_provider_approval(project, str(user.id), {
        'provider_name': 'provider-a',
        'provider_version': '1.0.0',
        'status': 'experimental',
        'capability': 'browser.discovery',
        'manifest': {
            'license': {'spdx': 'MIT'},
            'maintenance': {'status': 'active'},
            'sbom': True,
            'supply_chain_integrity': True,
            'known_cves': [],
            'container_privileges': [],
            'network_permissions': [],
            'output_quality': {},
            'determinism': True,
            'evidence_quality': True,
            'ci_reproducibility': True,
        },
        'rationale': 'fixture',
    })
    provider.status = 'approved'
    with pytest.raises(ValidationError, match='immutable'):
        provider.save()
    with pytest.raises(RuntimeError, match='immutable'):
        ProviderApprovalRecord.objects.filter(pk=provider.pk).delete()


@pytest.mark.django_db
def test_security_graph_upsert_is_idempotent_and_project_scoped():
    _user, project = _fixture()
    payload_nodes = [
        {
            'plane': 'identity',
            'kind': 'identity',
            'external_ref': 'identity:alice',
            'label': 'Alice',
            'tenant_ref': 'tenant-a',
            'properties': {'role': 'viewer'},
            'provenance': {'source': 'fixture'},
        },
        {
            'plane': 'application',
            'kind': 'endpoint',
            'external_ref': 'endpoint:GET:/orders/51',
            'label': '/orders/51',
            'protocol': 'https',
            'properties': {'method': 'GET'},
            'provenance': {'source': 'fixture'},
        },
    ]
    edges = [
        {
            'source_ref': 'identity:alice',
            'target_ref': 'endpoint:GET:/orders/51',
            'relation': 'calls',
            'evidence_refs': ['fixture-evidence'],
            'properties': {'observed': True},
            'provenance': {'source': 'fixture'},
        },
    ]
    first = upsert_graph_snapshot(project, payload_nodes, edges)
    assert first == {
        'nodes_created': 2,
        'nodes_updated': 0,
        'edges_created': 1,
        'edges_updated': 0,
    }

    payload_nodes[1]['properties'] = {'method': 'GET', 'sensitive': True}
    second = upsert_graph_snapshot(project, payload_nodes, edges)
    assert second == {
        'nodes_created': 0,
        'nodes_updated': 2,
        'edges_created': 0,
        'edges_updated': 1,
    }
    assert SecurityGraphNode.objects.filter(project=project).count() == 2
    assert SecurityGraphEdge.objects.filter(project=project).count() == 1
    endpoint = SecurityGraphNode.objects.get(project=project, kind='endpoint')
    assert endpoint.properties['sensitive'] is True


@pytest.mark.django_db
def test_validation_runs_and_observations_are_immutable_and_preserve_cross_tenant_lineage(settings):
    settings.SECRET_KEY = 'web-domain-lineage-test-secret'
    user, project = _fixture()
    persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': '*',
        'endpoint': '/records/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'record',
        'allowed': True,
        'ownership_rule': '',
        'tenant_rule': 'same_tenant',
        'sensitive_operation': False,
        'required_scopes': [],
        'conditions': {},
        'policy_source': 'application_rbac',
        'provenance': {'rbac_version': 'fixture-v1'},
        'confidence': 0.99,
        'version': 1,
    })
    cases = [
        {
            'ref': 'tenant-a-own',
            'identity': {'ref': 'svc-a', 'type': 'user', 'role': 'viewer', 'tenant_ref': 'tenant-a', 'scopes': []},
            'resource': {'ref': 'record-a', 'type': 'record', 'tenant_ref': 'tenant-a', 'owner_ref': ''},
            'endpoint': '/records/a',
            'method': 'GET',
            'operation': 'read',
            'protocol': 'https',
            'response': {'status_code': 200, 'headers': {}, 'body': {'tenant_id': 'tenant-a', 'value': 'own'}},
        },
        {
            'ref': 'tenant-a-to-b',
            'identity': {'ref': 'svc-a', 'type': 'user', 'role': 'viewer', 'tenant_ref': 'tenant-a', 'scopes': []},
            'resource': {'ref': 'record-b', 'type': 'record', 'tenant_ref': 'tenant-b', 'owner_ref': ''},
            'endpoint': '/records/b',
            'method': 'GET',
            'operation': 'read',
            'protocol': 'https',
            'response': {'status_code': 404, 'headers': {}, 'body': {'detail': 'Not found'}},
        },
    ]
    run, observations = run_authorization_matrix(project, str(user.id), cases)
    assert isinstance(run, WebSecurityValidationRun)
    assert run.summary['cross_tenant_cases'] == 1
    assert run.summary['failed'] == 0
    assert len(observations) == 2
    cross_tenant = WebSecurityObservation.objects.get(run=run, case_ref='tenant-a-to-b')
    assert cross_tenant.tenant_ref == 'tenant-a'
    assert cross_tenant.resource_tenant_ref == 'tenant-b'
    assert cross_tenant.expected_allowed is False
    assert cross_tenant.observed_decision == 'denied'
    assert cross_tenant.passed is True
    assert len(cross_tenant.evidence_fingerprint) == 64

    run.summary = {'tampered': True}
    with pytest.raises(ValidationError, match='immutable'):
        run.save()
    cross_tenant.passed = False
    with pytest.raises(ValidationError, match='immutable'):
        cross_tenant.save()
    with pytest.raises(RuntimeError, match='immutable'):
        WebSecurityObservation.objects.filter(run=run).update(passed=False)
