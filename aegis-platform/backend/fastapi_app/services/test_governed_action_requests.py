from __future__ import annotations

from uuid import uuid4

import pytest
from django.core.exceptions import ValidationError

from enterprise.governed_action_models import GovernedActionRequest
from fastapi_app.services.entity_capability_adapters import EntityCapabilityNotFound
from fastapi_app.services.governed_action_requests import (
    GovernedActionRequestConflict,
    GovernedActionRequestError,
    create_governed_action_request,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)


def _request(disposition_fixture, **overrides):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    values = {
        'project_id': str(project.id),
        'requested_by_id': str(user.id),
        'action_id': 'finding.disposition.accept_risk',
        'entity_type': 'finding',
        'entity_id': str(finding.id),
        'expected_version': finding.version,
        'idempotency_key': 'govreq-accept-risk-0001',
        'parameters': {'rationale': 'Request governed risk acceptance.'},
    }
    values.update(overrides)
    return create_governed_action_request(**values)


def test_request_is_immutable_scoped_and_idempotent(disposition_fixture):
    first = _request(disposition_fixture)
    second = _request(disposition_fixture)
    assert first.replayed is False
    assert second.replayed is True
    assert second.request.id == first.request.id
    assert first.request.action_id == 'finding.disposition.accept_risk'
    assert first.request.contract_version == 'agom.v1'
    assert first.request.contract_policy_version
    assert first.request.contract_snapshot['action_id'] == 'finding.disposition.accept_risk'
    assert len(first.request.contract_fingerprint) == 64
    assert len(first.request.request_fingerprint) == 64

    with pytest.raises(ValidationError):
        GovernedActionRequest.objects.filter(pk=first.request.id).update(entity_id=str(uuid4()))
    with pytest.raises(ValidationError):
        first.request.delete()


def test_idempotency_key_cannot_be_rebound(disposition_fixture):
    _request(disposition_fixture)
    with pytest.raises(GovernedActionRequestConflict, match='different governed action request'):
        _request(disposition_fixture, parameters={'rationale': 'Different immutable request.'})


def test_request_contract_entity_type_is_fail_closed(disposition_fixture):
    with pytest.raises(GovernedActionRequestError, match='entity_type'):
        _request(disposition_fixture, entity_type='campaign')


def test_request_requires_active_tenant_and_project_membership(disposition_fixture):
    _client, _user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    from django_project.users.models import User

    outsider = User.objects.create_user(
        email='govreq-outsider@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Outside',
        last_name='Requester',
    )
    with pytest.raises(PermissionError, match='Active tenant and project membership'):
        create_governed_action_request(
            project_id=str(project.id),
            requested_by_id=str(outsider.id),
            action_id='finding.disposition.accept_risk',
            entity_type='finding',
            entity_id=str(finding.id),
            expected_version=finding.version,
            idempotency_key='govreq-outsider-0001',
            parameters={},
        )


def test_request_rejects_unknown_or_cross_scope_entity(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, _finding, _organization, _membership = disposition_fixture
    with pytest.raises(EntityCapabilityNotFound):
        create_governed_action_request(
            project_id=str(project.id),
            requested_by_id=str(user.id),
            action_id='finding.disposition.accept_risk',
            entity_type='finding',
            entity_id=str(uuid4()),
            expected_version=1,
            idempotency_key='govreq-missing-entity-0001',
            parameters={},
        )


def test_exact_request_replay_does_not_reinterpret_current_contract(disposition_fixture, monkeypatch):
    first = _request(disposition_fixture, idempotency_key='govreq-policy-stable-replay-0001')
    monkeypatch.setattr(
        'fastapi_app.services.governed_action_requests.get_action_contract',
        lambda _action_id: None,
    )
    second = _request(disposition_fixture, idempotency_key='govreq-policy-stable-replay-0001')
    assert second.replayed is True
    assert second.request.id == first.request.id
    assert second.request.contract_fingerprint == first.request.contract_fingerprint
