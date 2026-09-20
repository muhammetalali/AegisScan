from __future__ import annotations

import pytest

from enterprise.governed_action_models import GovernedActionExecution
from enterprise.governed_responsibility_models import GovernedResponsibilityAssignment
from enterprise.models import OrganizationMembership
from fastapi_app.services.governed_responsibility_authority import grant_responsibility
from fastapi_app.services.test_campaign_objective_assurance import _setup
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def _grant_assessor(*, user, project, campaign):
    membership = OrganizationMembership.objects.get(organization=campaign.organization, user=user)
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])
    grant_responsibility(
        organization_id=str(campaign.organization_id),
        actor_id=str(user.id),
        membership_id=str(membership.id),
        responsibility='campaign_assessor',
        scope_kind=GovernedResponsibilityAssignment.ScopeKind.PROJECT,
        project_id=str(project.id),
        reason='API Reality campaign assessment duty.',
        idempotency_key=f'api-assessor-{campaign.id}',
    )


def _generic_body(*, project, campaign, objective, path, evidence, blast):
    return {
        'action_id': 'campaign.objective.assess',
        'project_id': str(project.id),
        'entity_type': 'crown_jewel_objective',
        'entity_id': str(objective.id),
        'expected_version': objective.version,
        'idempotency_key': 'generic-objective-assess-1',
        'parameters': {
            'campaign_id': str(campaign.id),
            'attack_path_id': str(path.id),
            'evidence_id': str(evidence.id),
            'blast_radius_snapshot_id': str(blast.id),
            'outcome': 'reached',
            'reason_code': 'validated_path',
            'explanation': 'Generic governed action API Reality proof.',
        },
    }


def test_generic_governed_action_api_executes_and_exactly_replays(disposition_fixture):
    client, user, project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    user, project, _asset, campaign, objective, path, evidence, blast = _setup(disposition_fixture)
    _grant_assessor(user=user, project=project, campaign=campaign)
    body = _generic_body(project=project, campaign=campaign, objective=objective, path=path, evidence=evidence, blast=blast)

    first = client.post('/api/v1/assurance/governance/actions/execute', json=body)
    second = client.post('/api/v1/assurance/governance/actions/execute', json=body)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()['execution_id'] == second.json()['execution_id']
    assert first.json()['replayed'] is False
    assert second.json()['replayed'] is True
    assert first.json()['result']['outcome'] == 'reached'
    assert len(first.json()['audit']['entry_hash']) == 64


def test_generic_api_requires_immutable_request_for_request_bound_action(disposition_fixture):
    client, _user, project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    response = client.post(
        '/api/v1/assurance/governance/actions/execute',
        json={
            'action_id': 'detection.publish',
            'project_id': str(project.id),
            'entity_type': 'detection_revision',
            'entity_id': '00000000-0000-0000-0000-000000000001',
            'expected_version': 1,
            'idempotency_key': 'unsupported-action',
            'parameters': {},
        },
    )
    assert response.status_code == 400
    assert 'requires an immutable request_id' in response.text


def test_generic_api_rejects_client_asserted_authority_fields(disposition_fixture):
    client, _user, project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    response = client.post(
        '/api/v1/assurance/governance/actions/execute',
        json={
            'action_id': 'campaign.complete',
            'project_id': str(project.id),
            'entity_type': 'campaign',
            'entity_id': '00000000-0000-0000-0000-000000000001',
            'expected_version': 1,
            'idempotency_key': 'forged-authority',
            'parameters': {},
            'actor_role': 'owner',
            'actor_responsibilities': ['campaign_lead'],
        },
    )
    assert response.status_code == 422


def test_legacy_campaign_assessment_route_has_no_direct_mutation_bypass(disposition_fixture):
    client, _user, _project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    user, project, _asset, campaign, objective, path, evidence, blast = _setup(disposition_fixture)
    _grant_assessor(user=user, project=project, campaign=campaign)
    response = client.post(
        f'/api/v1/attack-path/campaigns/projects/{project.id}/{campaign.id}/objectives/{objective.id}/assessments',
        json={
            'expected_objective_version': objective.version,
            'idempotency_key': 'legacy-governed-assessment',
            'attack_path_id': str(path.id),
            'evidence_id': str(evidence.id),
            'blast_radius_snapshot_id': str(blast.id),
            'outcome': 'reached',
            'reason_code': 'validated_path',
            'explanation': 'Legacy route is governed by the executor.',
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload['execution_id']
    assert len(payload['execution_fingerprint']) == 64
    assert len(payload['audit_entry_hash']) == 64
    assert GovernedActionExecution.objects.filter(pk=payload['execution_id']).exists()


def test_legacy_campaign_assessment_requires_idempotency_key(disposition_fixture):
    client, _user, _project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    user, project, _asset, campaign, objective, path, evidence, _blast = _setup(disposition_fixture)
    _grant_assessor(user=user, project=project, campaign=campaign)
    response = client.post(
        f'/api/v1/attack-path/campaigns/projects/{project.id}/{campaign.id}/objectives/{objective.id}/assessments',
        json={
            'expected_objective_version': objective.version,
            'attack_path_id': str(path.id),
            'evidence_id': str(evidence.id),
            'outcome': 'blocked',
            'reason_code': 'control_prevented_progression',
        },
    )
    assert response.status_code == 422
