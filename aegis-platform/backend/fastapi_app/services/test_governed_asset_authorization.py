from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.users.models import User
from enterprise.governed_action_models import GovernedActionExecution, GovernedActionRequest
from enterprise.models import OrganizationMembership
from fastapi_app.routers.assets import _normalize_import_row
from fastapi_app.services.asset_authorization_governance import (
    AssetAuthorizationGovernanceError,
    asset_authorization_version,
    delete_asset_if_lineage_free,
    initialize_asset_configuration,
    replace_asset_configuration_preserving_authorization,
)
from fastapi_app.services.governed_action_executor import GovernedActionBlocked, execute_governed_action
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_finding_governed_actions import _actor


pytestmark = pytest.mark.django_db(transaction=True)


def _ownerize(membership):
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])


def _proposer(*, project, organization, marker: str):
    user = User.objects.create_user(
        email=f'a3-asset-proposer-{marker}@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Asset',
        last_name='Proposer',
    )
    project.members.add(user)
    OrganizationMembership.objects.create(
        organization=organization,
        user=user,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    return user


def _approver(*, owner, project, organization, marker: str):
    user, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email=f'a3-asset-approver-{marker}@example.invalid',
        role=OrganizationMembership.Role.ADMIN,
        responsibility='authorization_approver',
    )
    return user


def _request(*, project, asset, proposer, action_id: str, parameters: dict, marker: str):
    return create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(proposer.id),
        action_id=action_id,
        entity_type='asset',
        entity_id=str(asset.id),
        expected_version=asset_authorization_version(asset),
        idempotency_key=f'a3-asset-request-{marker}',
        parameters=parameters,
    ).request


def _execute(*, project, asset, approver, request, action_id: str, parameters: dict, marker: str):
    return execute_governed_action(
        action_id=action_id,
        project_id=str(project.id),
        actor_id=str(approver.id),
        entity_type='asset',
        entity_id=str(asset.id),
        expected_version=request.expected_version,
        idempotency_key=f'a3-asset-execution-{marker}',
        request_id=str(request.id),
        parameters=parameters,
    )


def test_legacy_asset_authorization_post_submits_request_without_mutation(disposition_fixture):
    client, owner, _project, asset, initial, _scan, _finding, _organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    before_configuration = dict(asset.configuration)
    before_count = AssetAuthorization.objects.filter(asset=asset).count()
    request_id = uuid4()

    response = client.post(
        f'/api/v1/assets/{asset.id}/authorization',
        json={'authorized': False, 'reason': 'Submit governed revocation for independent approval.'},
        headers={'X-Request-ID': str(request_id)},
    )

    assert response.status_code == 202, response.text
    body = response.json()
    assert body['status'] == 'submitted'
    assert body['governed_action']['action_id'] == 'asset.authorization.revoke'
    assert body['governed_action']['entity_type'] == 'asset'
    asset.refresh_from_db()
    assert asset.configuration == before_configuration
    assert AssetAuthorization.objects.filter(asset=asset).count() == before_count
    assert AssetAuthorization.objects.get(pk=initial.id).authorized is True
    assert GovernedActionRequest.objects.filter(
        id=body['governed_action']['request_id'],
        requested_by=owner,
    ).exists()


def test_legacy_asset_authorization_post_rejects_idempotency_rebinding_as_conflict(disposition_fixture):
    client, _owner, _project, asset, _initial, _scan, _finding, _organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    request_id = uuid4()

    first = client.post(
        f'/api/v1/assets/{asset.id}/authorization',
        json={'authorized': False, 'reason': 'First immutable governed revocation proposal.'},
        headers={'X-Request-ID': str(request_id)},
    )
    assert first.status_code == 202, first.text

    rebound = client.post(
        f'/api/v1/assets/{asset.id}/authorization',
        json={'authorized': False, 'reason': 'Different payload must not rebind the same request id.'},
        headers={'X-Request-ID': str(request_id)},
    )
    assert rebound.status_code == 409, rebound.text
    assert GovernedActionRequest.objects.filter(
        id=first.json()['governed_action']['request_id'],
        entity_id=str(asset.id),
    ).count() == 1


def test_request_bound_asset_revoke_and_reapprove_are_atomic_and_versioned(disposition_fixture):
    _client, owner, project, asset, initial, _scan, _finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    proposer = _proposer(project=project, organization=organization, marker='revoke')
    approver = _approver(owner=owner, project=project, organization=organization, marker='revoke')
    revoke_parameters = {'reason': 'Governed scope revocation approved by independent authority.'}
    revoke_request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=revoke_parameters,
        marker='revoke',
    )
    before_version = revoke_request.expected_version
    revoked = _execute(
        project=project,
        asset=asset,
        approver=approver,
        request=revoke_request,
        action_id='asset.authorization.revoke',
        parameters=revoke_parameters,
        marker='revoke',
    )

    asset.refresh_from_db()
    revoke_decision = AssetAuthorization.objects.get(pk=revoked.execution.result_payload['authorization_decision_id'])
    assert revoke_decision.authorized is False
    assert revoke_decision.supersedes_id == initial.id
    assert revoke_decision.request_id == revoke_request.id
    assert revoke_decision.correlation_id == revoke_request.correlation_id
    assert asset.configuration['authorized'] is False
    assert revoked.execution.result_payload['version'] == before_version + 1
    assert GovernedActionExecution.objects.filter(request=revoke_request).count() == 1
    assert AuditLog.objects.filter(
        metadata__governed_action_id='asset.authorization.revoke',
        resource_id=str(asset.id),
    ).count() == 1

    proposer2 = _proposer(project=project, organization=organization, marker='approve')
    approver2 = _approver(owner=owner, project=project, organization=organization, marker='approve')
    expiry = (datetime.now(timezone.utc) + timedelta(days=45)).isoformat()
    approve_parameters = {
        'reason': 'Renew governed scope after independent review.',
        'expires_at': expiry,
    }
    approve_request = _request(
        project=project,
        asset=asset,
        proposer=proposer2,
        action_id='asset.authorization.approve',
        parameters=approve_parameters,
        marker='approve',
    )
    approved = _execute(
        project=project,
        asset=asset,
        approver=approver2,
        request=approve_request,
        action_id='asset.authorization.approve',
        parameters=approve_parameters,
        marker='approve',
    )
    asset.refresh_from_db()
    approve_decision = AssetAuthorization.objects.get(pk=approved.execution.result_payload['authorization_decision_id'])
    assert approve_decision.authorized is True
    assert approve_decision.supersedes_id == revoke_decision.id
    assert approve_decision.request_id == approve_request.id
    assert approve_decision.expires_at is not None
    assert asset.configuration['authorized'] is True
    assert approved.execution.result_payload['version'] == approve_request.expected_version + 1


def test_asset_authorization_self_approval_is_blocked(disposition_fixture):
    _client, owner, project, asset, _initial, _scan, _finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    approver = _approver(owner=owner, project=project, organization=organization, marker='self')
    parameters = {'reason': 'Self approval must never authorize scope.'}
    request = _request(
        project=project,
        asset=asset,
        proposer=approver,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='self',
    )
    before_count = AssetAuthorization.objects.filter(asset=asset).count()

    with pytest.raises(GovernedActionBlocked) as blocked:
        _execute(
            project=project,
            asset=asset,
            approver=approver,
            request=request,
            action_id='asset.authorization.revoke',
            parameters=parameters,
            marker='self',
        )

    assert blocked.value.reason_code == 'SOD_VIOLATION'
    asset.refresh_from_db()
    assert asset.configuration['authorized'] is True
    assert AssetAuthorization.objects.filter(asset=asset).count() == before_count


def test_asset_authorization_rolls_back_when_agom_audit_fails(disposition_fixture, monkeypatch):
    _client, owner, project, asset, _initial, _scan, _finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    proposer = _proposer(project=project, organization=organization, marker='rollback')
    approver = _approver(owner=owner, project=project, organization=organization, marker='rollback')
    parameters = {'reason': 'Audit failure must roll back authorization mutation.'}
    request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='rollback',
    )
    before_count = AssetAuthorization.objects.filter(asset=asset).count()
    before_configuration = dict(asset.configuration)

    def _fail_audit(**_kwargs):
        raise RuntimeError('forced AGOM audit append failure')

    monkeypatch.setattr('fastapi_app.services.governed_action_executor.append_audit', _fail_audit)
    with pytest.raises(RuntimeError, match='forced AGOM audit'):
        _execute(
            project=project,
            asset=asset,
            approver=approver,
            request=request,
            action_id='asset.authorization.revoke',
            parameters=parameters,
            marker='rollback',
        )

    asset.refresh_from_db()
    assert asset.configuration == before_configuration
    assert AssetAuthorization.objects.filter(asset=asset).count() == before_count
    assert GovernedActionExecution.objects.filter(request=request).count() == 0



def test_asset_configuration_projection_is_server_owned_and_preserved(disposition_fixture):
    _client, _owner, project, asset, _initial, _scan, _finding, _organization, _membership = disposition_fixture
    before_count = AssetAuthorization.objects.filter(asset=asset).count()

    with pytest.raises(AssetAuthorizationGovernanceError, match='server-owned'):
        initialize_asset_configuration({'host': 'example.invalid', 'authorized': True})
    with pytest.raises(AssetAuthorizationGovernanceError, match='server-owned'):
        replace_asset_configuration_preserving_authorization(
            asset.configuration,
            {'host': 'replacement.invalid', 'authorized': False},
        )

    replacement = replace_asset_configuration_preserving_authorization(
        asset.configuration,
        {'host': 'replacement.invalid'},
    )
    assert replacement['host'] == 'replacement.invalid'
    assert replacement['authorized'] is True
    assert AssetAuthorization.objects.filter(asset=asset).count() == before_count

    with pytest.raises(ValueError, match='server-owned authorization'):
        _normalize_import_row(
            {
                'name': 'Bypass import',
                'type': 'ip_address',
                'host': '192.0.2.10',
                'authorized': True,
            },
            str(project.id),
        )



def test_asset_hard_delete_is_blocked_when_governance_lineage_exists(disposition_fixture):
    _client, _owner, _project, asset, initial, _scan, _finding, _organization, _membership = disposition_fixture
    asset_id = asset.id
    authorization_id = initial.id

    with pytest.raises(AssetAuthorizationGovernanceError, match='durable security/governance lineage'):
        delete_asset_if_lineage_free(asset_id=str(asset_id))

    assert Asset.objects.filter(pk=asset_id).exists()
    preserved = AssetAuthorization.objects.get(pk=authorization_id)
    assert preserved.asset_id == asset_id


def test_asset_hard_delete_allows_truly_unused_asset(disposition_fixture):
    _client, owner, project, _asset, _initial, _scan, _finding, _organization, _membership = disposition_fixture
    unused = Asset.objects.create(
        project=project,
        owner=owner,
        name='Unused disposable asset',
        slug='unused-disposable-asset',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '192.0.2.250', 'authorized': False},
    )
    asset_id = unused.id

    delete_asset_if_lineage_free(asset_id=str(asset_id))

    assert not Asset.objects.filter(pk=asset_id).exists()
