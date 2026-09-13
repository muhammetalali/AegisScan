from __future__ import annotations

import pytest

from enterprise.models import OrganizationMembership
from fastapi_app.main import app
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def test_entity_capability_api_exposes_no_client_authority_inputs(disposition_fixture):
    client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    schema = app.openapi()
    path = '/api/v1/assurance/governance/capabilities/{entity_type}/{entity_id}'
    assert path in schema['paths']
    operation = schema['paths'][path]['get']
    parameters = {item['name'] for item in operation.get('parameters', [])}
    assert parameters == {'entity_type', 'entity_id', 'project_id'}
    forbidden = {
        'actor_layer', 'actor_role', 'actor_responsibilities', 'responsibilities',
        'lifecycle', 'state', 'evidence_ready', 'sod_eligible', 'gate_results',
    }
    assert parameters.isdisjoint(forbidden)
    assert 'requestBody' not in operation

    response = client.get(
        f'/api/v1/assurance/governance/capabilities/finding/{finding.id}',
        params={'project_id': str(project.id)},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['entity']['entity_type'] == 'finding'
    assert payload['entity']['entity_id'] == str(finding.id)
    assert payload['actor_role'] == OrganizationMembership.Role.MANAGER
    assert 'actor_layer' not in payload
    assert 'actor_responsibilities' in payload
    assert payload['evaluation_policy_version'] == 'agom-entity-capability.v1'
    assert payload['capabilities']
    assert all('evaluated_actor_layer' in item for item in payload['capabilities'])


def test_entity_capability_api_rejects_unsupported_type_without_accepting_authority_overrides(disposition_fixture):
    client, _user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    response = client.get(
        f'/api/v1/assurance/governance/capabilities/not_a_domain/{finding.id}',
        params={
            'project_id': str(project.id),
            'actor_layer': 'govern',
            'actor_role': 'owner',
            'evidence_ready': 'true',
        },
    )
    # Unknown query parameters are ignored by FastAPI, but they are not part of
    # the operation contract and cannot influence server-derived authority.
    assert response.status_code == 400
    assert 'Unsupported AGOM entity type' in response.json()['detail']
