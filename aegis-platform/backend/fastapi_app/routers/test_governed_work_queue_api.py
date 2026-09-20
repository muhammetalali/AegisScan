from __future__ import annotations

import pytest

from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.test_finding_disposition import disposition_fixture


pytestmark = pytest.mark.django_db(transaction=True)


def test_work_queue_api_lists_and_claims_with_server_actor(disposition_fixture):
    client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    request = create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(user.id),
        action_id='finding.disposition.accept_risk',
        entity_type='finding',
        entity_id=str(finding.id),
        expected_version=finding.version,
        idempotency_key='a5-api-request-0001',
        parameters={'rationale': 'A5 API queue request.'},
    ).request

    listing = client.get(f'/api/v1/work-queue?project_id={project.id}')
    assert listing.status_code == 200, listing.text
    payload = listing.json()
    item = next(item for item in payload['items'] if item['source_id'] == str(request.id))
    assert item['claim']['version'] == 0

    claim = client.post(
        f'/api/v1/work-queue/governed_action_request/{request.id}/claim',
        json={
            'project_id': str(project.id),
            'expected_claim_version': 0,
            'idempotency_key': 'a5-api-claim-0001',
            'lease_seconds': 300,
        },
    )
    assert claim.status_code == 200, claim.text
    claimed = claim.json()
    assert claimed['claim']['claimed_by_id'] == str(user.id)
    assert claimed['claim']['version'] == 1
    assert claimed['replayed'] is False

    replay = client.post(
        f'/api/v1/work-queue/governed_action_request/{request.id}/claim',
        json={
            'project_id': str(project.id),
            'expected_claim_version': 0,
            'idempotency_key': 'a5-api-claim-0001',
            'lease_seconds': 300,
        },
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()['replayed'] is True


def test_work_queue_api_rejects_client_actor_and_unknown_fields(disposition_fixture):
    client, _user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    response = client.post(
        f'/api/v1/work-queue/governed_action_request/{finding.id}/claim',
        json={
            'project_id': str(project.id),
            'expected_claim_version': 0,
            'idempotency_key': 'a5-api-extra-0001',
            'lease_seconds': 300,
            'claimed_by_id': 'attacker-controlled',
        },
    )
    assert response.status_code == 422
