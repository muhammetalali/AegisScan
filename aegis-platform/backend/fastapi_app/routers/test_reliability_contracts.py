from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from asgiref.sync import async_to_sync
from django.db import close_old_connections

from django_project.assets.models import Asset, AssetAuthorization, AssetRelationship
from django_project.projects.models import Project
from django_project.users.models import User, UserRole
from fastapi_app.core.dependencies import get_current_user as core_get_current_user
from fastapi_app.main import app
from fastapi_app.routers.assets import get_current_user as asset_get_current_user
from fastapi.testclient import TestClient

pytestmark = pytest.mark.django_db(transaction=True)


def _auth(user):
    identity = lambda: {'user_id': str(user.id)}
    app.dependency_overrides[core_get_current_user] = identity
    app.dependency_overrides[asset_get_current_user] = identity


def _clear_auth():
    app.dependency_overrides.pop(core_get_current_user, None)
    app.dependency_overrides.pop(asset_get_current_user, None)


def test_negative_scan_scope_is_enforced():
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    user = User.objects.create_user(email='negative-scan@example.invalid', password='Strong-Test-Password-123!', role=UserRole.SECURITY_ANALYST)
    project = Project.objects.create(name='Negative Scan', slug='negative-scan', owner=user)
    with pytest.raises(Exception) as exc:
        async_to_sync(_create_scan)(ScanCreate(project_id=str(project.id), name='blocked', scan_type='network', engines=['nmap'], config={'target': 'not-authorized.invalid'}), str(user.id))
    assert 'authorization' in str(exc.value).lower() or 'authorized' in str(exc.value).lower()


def test_scan_target_is_bound_to_authorized_asset_identity(monkeypatch):
    from fastapi import HTTPException
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    user = User.objects.create_user(email='bound-scan@example.invalid', password='Strong-Test-Password-123!', role=UserRole.SECURITY_ANALYST)
    project = Project.objects.create(name='Bound Scan', slug='bound-scan', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Bound target',
        slug='bound-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '10.30.0.10', 'authorized': True},
    )
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '10.30.0.0/24')

    with pytest.raises(HTTPException) as exc:
        async_to_sync(_create_scan)(
            ScanCreate(
                project_id=str(project.id),
                name='target substitution',
                scan_type='ip',
                asset_id=str(asset.id),
                engines=['nmap'],
                config={'target': '169.254.169.254'},
                authorized=True,
            ),
            str(user.id),
        )

    assert exc.value.status_code == 409
    assert not project.scans.exists()


def test_configuration_authorized_flag_does_not_replace_authoritative_decision(monkeypatch):
    from fastapi import HTTPException
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    user = User.objects.create_user(email='server-scope@example.invalid', password='Strong-Test-Password-123!', role=UserRole.SECURITY_ANALYST)
    project = Project.objects.create(name='Server Scope', slug='server-scope', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Asset authorization alone is insufficient',
        slug='insufficient-authorization',
        type=Asset.Type.IP_ADDRESS,
        configuration={'host': '10.40.0.10', 'authorized': True},
    )
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '10.50.0.0/24')

    with pytest.raises(HTTPException) as exc:
        async_to_sync(_create_scan)(
            ScanCreate(
                project_id=str(project.id),
                name='outside server scope',
                scan_type='ip',
                asset_id=str(asset.id),
                engines=['nmap'],
            ),
            str(user.id),
        )

    assert exc.value.status_code == 403
    assert not project.scans.exists()


def test_exact_bound_private_ip_authorization_allows_scan_without_static_allowlist(monkeypatch):
    from fastapi_app.routers.scans import _create_scan, ScanCreate

    monkeypatch.delenv('AUTHORIZED_SCAN_TARGETS', raising=False)
    user = User.objects.create_user(email='dynamic-private-scan@example.invalid', password='Strong-Test-Password-123!', role=UserRole.SECURITY_ANALYST)
    project = Project.objects.create(name='Dynamic Private Scan', slug='dynamic-private-scan', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Exact private target',
        slug='exact-private-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'ip': '10.40.0.10', 'authorized': True},
    )
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='10.40.0.10',
        reason='exact governed private target',
    )

    scan, engines = async_to_sync(_create_scan)(
        ScanCreate(
            project_id=str(project.id),
            name='exact private nmap',
            scan_type='ip',
            asset_id=str(asset.id),
            engines=['nmap'],
        ),
        str(user.id),
    )

    assert engines == ['nmap']
    assert scan.asset_id == asset.id
    assert scan.authorization_decision_id == decision.id


def test_attack_path_persistence_is_idempotent():
    user = User.objects.create_user(email='idempotent@example.invalid', password='Strong-Test-Password-123!', role=UserRole.SECURITY_ANALYST)
    project = Project.objects.create(name='Idempotency', slug='idempotency', owner=user)
    source = Asset.objects.create(project=project, name='Source', slug='source', type=Asset.Type.WEBSITE, configuration={'internet_exposed': True})
    target = Asset.objects.create(project=project, name='Target', slug='target', type=Asset.Type.CLOUD_RESOURCE, criticality=Asset.Criticality.HIGH)
    AssetRelationship.objects.create(project=project, source=source, target=target, relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO)
    _auth(user)
    try:
        client = TestClient(app)
        body = {'source_asset_id': str(source.id), 'target_asset_id': str(target.id), 'max_hops': 2}
        first = client.post(f'/api/v1/attack-path/projects/{project.id}/analyze', json=body)
        second = client.post(f'/api/v1/attack-path/projects/{project.id}/analyze', json=body)
    finally:
        _clear_auth()
        close_old_connections()
    assert first.status_code == second.status_code == 200
    assert first.json()['persisted_attack_path_ids'] == second.json()['persisted_attack_path_ids']


def test_relationship_creation_is_concurrency_safe():
    user = User.objects.create_user(email='concurrency@example.invalid', password='Strong-Test-Password-123!', role=UserRole.SECURITY_ANALYST)
    project = Project.objects.create(name='Concurrency', slug='concurrency', owner=user)
    source = Asset.objects.create(project=project, name='Source', slug='source', type=Asset.Type.WEBSITE, configuration={'internet_exposed': True})
    target = Asset.objects.create(project=project, name='Target', slug='target', type=Asset.Type.API_ENDPOINT)
    _auth(user)

    def create_once():
        close_old_connections()
        client = TestClient(app)
        response = client.post(f'/api/v1/assets/{source.id}/relationships', params={'target_id': str(target.id), 'relationship_type': 'connects_to'})
        close_old_connections()
        return response.status_code

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda _: create_once(), range(2)))
    finally:
        _clear_auth()
        close_old_connections()
    assert all(status in {200, 201} for status in statuses)
    assert AssetRelationship.objects.filter(project=project, source=source, target=target, relationship_type='connects_to').count() == 1


def _tenant_binding_fixture(suffix='a'):
    from enterprise.models import Organization, OrganizationMembership

    actor = User.objects.create_user(
        email=f'tenant-reconcile-{suffix}@example.invalid',
        password='Strong-Test-Password-123!',
        role=UserRole.SECURITY_ANALYST,
    )
    project = Project.objects.create(
        name=f'Tenant reconcile {suffix}', slug=f'tenant-reconcile-{suffix}', owner=actor,
    )
    organizations = []
    for label in ('primary', 'secondary'):
        organization = Organization.objects.create(
            name=f'Tenant {suffix} {label}',
            slug=f'tenant-{suffix}-{label}',
            owner=actor,
        )
        OrganizationMembership.objects.create(
            organization=organization,
            user=actor,
            role=OrganizationMembership.Role.OWNER,
            is_active=True,
        )
        organizations.append(organization)
    return actor, project, *organizations


def test_tenant_binding_read_reconciliation_and_conflicting_replay_fail_closed():
    """Lost HTTP response must not allow an existing project to move tenants."""
    from enterprise.models import TenantProject

    actor, project, primary, secondary = _tenant_binding_fixture('replay')
    endpoint = f'/api/v1/enterprise/projects/{project.id}/tenant'
    _auth(actor)
    try:
        with TestClient(app) as client:
            not_bound = client.get(endpoint)
            assert not_bound.status_code == 404

            # Simulate committing the POST but losing its HTTP response at
            # the client boundary: reconciliation MUST be a read, not a retry.
            first_response = client.post(endpoint, params={'organization_id': str(primary.id)})
            assert first_response.status_code == 200, first_response.text
            del first_response
            reconciled = client.get(endpoint)
            assert reconciled.status_code == 200, reconciled.text
            assert reconciled.json() == {
                'project_id': str(project.id),
                'organization_id': str(primary.id),
                'bound': True,
            }
            repeat = client.post(endpoint, params={'organization_id': str(primary.id)})
            assert repeat.status_code == 200, repeat.text
            assert repeat.json()['created'] is False

            conflicting = client.post(endpoint, params={'organization_id': str(secondary.id)})
            assert conflicting.status_code == 409
            assert 'no automatic tenant reassignment' in conflicting.json()['detail']
    finally:
        _clear_auth()
        close_old_connections()

    links = TenantProject.objects.filter(project=project)
    assert links.count() == 1
    assert links.get().organization_id == primary.pk


def test_tenant_binding_requires_active_admin_and_reconciliation_hides_other_tenant():
    from enterprise.models import OrganizationMembership, TenantProject

    actor, project, primary, secondary = _tenant_binding_fixture('visibility')
    endpoint = f'/api/v1/enterprise/projects/{project.id}/tenant'
    _auth(actor)
    try:
        with TestClient(app) as client:
            success = client.post(endpoint, params={'organization_id': str(primary.id)})
            assert success.status_code == 200, success.text
            assert TenantProject.objects.get(project=project).organization_id == primary.pk

            OrganizationMembership.objects.filter(organization=primary, user=actor).update(
                is_active=False,
            )
            hidden = client.get(endpoint)
            assert hidden.status_code == 404
            denied = client.post(endpoint, params={'organization_id': str(primary.id)})
            assert denied.status_code == 403
            assert TenantProject.objects.get(project=project).organization_id == primary.pk

            OrganizationMembership.objects.filter(organization=primary, user=actor).update(
                is_active=True,
            )
            secondary.is_active = False
            secondary.save(update_fields=['is_active'])
            inactive_target = client.post(endpoint, params={'organization_id': str(secondary.id)})
            assert inactive_target.status_code == 404
            assert client.get(endpoint).json()['organization_id'] == str(primary.id)
    finally:
        _clear_auth()
        close_old_connections()


def test_tenant_binding_failure_rolls_back_link_without_half_committed_membership(monkeypatch):
    """The link and owner-membership persistence share one transaction."""
    from enterprise.models import OrganizationMembership, TenantProject

    actor, project, primary, _ = _tenant_binding_fixture('rollback')
    endpoint = f'/api/v1/enterprise/projects/{project.id}/tenant'
    before_count = TenantProject.objects.filter(project=project).count()
    original_get_or_create = OrganizationMembership.objects.get_or_create

    def fail_after_link(*args, **kwargs):
        if kwargs.get('organization') == primary and kwargs.get('user') == actor:
            raise RuntimeError('injected rollback after tenant link insert')
        return original_get_or_create(*args, **kwargs)

    monkeypatch.setattr(OrganizationMembership.objects, 'get_or_create', fail_after_link)
    _auth(actor)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            failed = client.post(endpoint, params={'organization_id': str(primary.id)})
            assert failed.status_code == 500
    finally:
        _clear_auth()
        close_old_connections()
    assert TenantProject.objects.filter(project=project).count() == before_count
