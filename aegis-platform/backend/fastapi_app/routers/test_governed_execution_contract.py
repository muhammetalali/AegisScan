from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.routers import capabilities as capabilities_router


pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def governed_execution_fixture(monkeypatch):
    user = User.objects.create_user(
        email='governed-execution@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Governed',
        last_name='Execution',
    )
    project = Project.objects.create(
        name='Governed Execution Contract',
        slug='governed-execution-contract',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name='governed-web-target',
        slug='governed-web-target',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://example.test/'},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='https://example.test/',
        reason='governed execution contract reality',
    )

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(user.id),
        'is_staff': True,
    }

    dispatches: list[str] = []

    def fake_delay(scan_id: str):
        dispatches.append(scan_id)
        return SimpleNamespace(id=f'contract-task-{scan_id}')

    monkeypatch.setattr(capabilities_router.run_native_capability_scan, 'delay', fake_delay)

    with TestClient(app) as client:
        try:
            yield client, user, project, asset, authorization, dispatches
        finally:
            app.dependency_overrides.clear()


def _payload(project: Project, asset: Asset, *, depth: str = 'standard', correlation_id: str = 'corr-core-0001') -> dict:
    return {
        'project_id': str(project.id),
        'asset_id': str(asset.id),
        'depth': depth,
        'options': {},
        'credential_refs': [],
        'idempotency_key': 'idem-core-0001',
        'correlation_id': correlation_id,
    }


def test_capability_execution_persists_server_owned_execution_envelope(governed_execution_fixture):
    client, user, project, asset, authorization, dispatches = governed_execution_fixture

    response = client.post(
        '/api/v1/capabilities/web.http-method-policy/execute',
        json=_payload(project, asset),
    )

    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload['idempotency_reused'] is False
    assert payload['correlation_id'] == 'corr-core-0001'
    assert len(dispatches) == 1

    scan = Scan.objects.get(id=payload['scan']['id'])
    assert scan.execution_idempotency_key == 'idem-core-0001'
    assert len(scan.execution_idempotency_fingerprint) == 64
    assert len(scan.execution_contract_fingerprint) == 64

    envelope = scan.execution_contract
    assert envelope == payload['execution_contract']
    assert envelope['contract_version'] == '1.0'
    assert envelope['policy_version'] == 'capability-execution.v4'
    assert envelope['actor_ref'] == f'user:{user.id}'
    assert envelope['tenant_scope_ref'] == f'project:{project.id}'
    assert envelope['project_ref'] == f'project:{project.id}'
    assert envelope['asset_ref'] == f'asset:{asset.id}'
    assert envelope['authorization_ref'] == f'authorization:{authorization.id}'
    assert envelope['requested_capability_id'] == 'web.http-method-policy'
    assert envelope['capability_id'] == 'web.http-method-policy'
    assert envelope['runner_profile'] == 'web'
    assert envelope['execution_mode'] == 'isolated-celery'
    assert envelope['risk_class'] == 'active-low'
    assert envelope['methodology_refs'] == ['WSTG-v42-CONF-06']
    assert envelope['allowed_options'] == {}
    assert envelope['credential_bindings'] == []
    assert envelope['idempotency_key'] == 'idem-core-0001'
    assert envelope['correlation_id'] == 'corr-core-0001'
    assert len(envelope['policy_fingerprint']) == 64


def test_same_idempotency_key_reuses_scan_without_second_dispatch(governed_execution_fixture):
    client, _user, project, asset, _authorization, dispatches = governed_execution_fixture

    first = client.post(
        '/api/v1/capabilities/web.http-method-policy/execute',
        json=_payload(project, asset, correlation_id='corr-core-first'),
    )
    second = client.post(
        '/api/v1/capabilities/web.http-method-policy/execute',
        json=_payload(project, asset, correlation_id='corr-core-retry'),
    )

    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    first_payload = first.json()
    second_payload = second.json()
    assert second_payload['idempotency_reused'] is True
    assert second_payload['scan']['id'] == first_payload['scan']['id']
    assert second_payload['correlation_id'] == 'corr-core-first'
    assert second_payload['execution_contract'] == first_payload['execution_contract']
    assert len(dispatches) == 1
    assert Scan.objects.filter(project=project).count() == 1


def test_idempotency_key_rejects_semantic_request_drift(governed_execution_fixture):
    client, _user, project, asset, _authorization, dispatches = governed_execution_fixture

    first = client.post(
        '/api/v1/capabilities/web.http-method-policy/execute',
        json=_payload(project, asset, depth='standard'),
    )
    conflict = client.post(
        '/api/v1/capabilities/web.http-method-policy/execute',
        json=_payload(project, asset, depth='deep', correlation_id='corr-core-0002'),
    )

    assert first.status_code == 202, first.text
    assert conflict.status_code == 409, conflict.text
    assert 'already bound to a different governed request' in conflict.json()['detail']
    assert len(dispatches) == 1
    assert Scan.objects.filter(project=project).count() == 1


def test_client_cannot_supply_authorization_or_methodology_authority(governed_execution_fixture):
    client, _user, project, asset, _authorization, dispatches = governed_execution_fixture
    body = _payload(project, asset)
    body['authorization_ref'] = 'authorization:client-forged'
    body['methodology_refs'] = ['WSTG-v42-CLNT-11']
    body['runner_profile'] = 'full'

    response = client.post(
        '/api/v1/capabilities/web.http-method-policy/execute',
        json=body,
    )

    assert response.status_code == 422
    assert dispatches == []
    assert Scan.objects.filter(project=project).count() == 0
