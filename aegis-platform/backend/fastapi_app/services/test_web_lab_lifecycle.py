from __future__ import annotations

import time
from uuid import uuid4

import pytest
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.models import Organization, OrganizationMembership, TenantProject
from enterprise.web_lab_models import WebLabInstance, WebLabLifecycleEvent
from fastapi_app.services import web_lab_lifecycle as lifecycle
from fastapi_app.services.web_labs_preparation import lab_definition


pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setenv('AEGIS_EVIDENCE_HMAC_KEY', 'p5-test-evidence-key-' + ('x' * 40))
    user = User.objects.create_user(email='web-lab-lifecycle@example.invalid', password='test-only')
    project = Project.objects.create(name='Web Lab Lifecycle', slug='web-lab-lifecycle', owner=user)
    target = 'http://127.0.0.1:18081'
    asset = Asset.objects.create(
        project=project, name='Sealed BAC Fixture', slug='sealed-bac-fixture',
        type=Asset.Type.WEBSITE, configuration={'url': target, 'authorized': True},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=True, target_snapshot=target,
    )
    organization = Organization.objects.create(
        name='Web Lab Lifecycle Tenant', slug='web-lab-lifecycle-tenant', owner=user,
    )
    OrganizationMembership.objects.create(
        organization=organization, user=user, is_active=True,
        role=OrganizationMembership.Role.MANAGER,
    )
    TenantProject.objects.create(organization=organization, project=project)
    return user, project, asset, authorization, organization


def inspection(*, target='http://127.0.0.1:18081', variant='vulnerable',
               container_id=None, instance_ref=None):
    definition = lab_definition('bac-orders-v1')
    return {
        'target': target,
        'instance_ref': str(instance_ref or uuid4()),
        'process_ref': str(uuid4()),
        'fixture_revision': definition['fixture_revision_sha256'],
        'variant': variant,
        'image_id': 'sha256:' + ('a' * 64),
        'container_id': container_id or ('b' * 64),
        'inspected_at': time.time(),
    }


def provision(context, *, key='p5-provision-1', runtime=None, supersedes=None, name='aegis-web-lab-a1b2c3d4e5f6'):
    user, _project, asset, *_ = context
    return lifecycle.register_provisioned_instance(
        actor_id=str(user.id), asset_id=str(asset.id), lab_definition_id='bac-orders-v1',
        inspection=runtime or inspection(), container_name=name, ttl_seconds=600,
        idempotency_key=key, supersedes_instance_id=supersedes,
    )


def test_provision_is_idempotent_and_event_chain_is_append_only(context):
    first_runtime = inspection()
    first = provision(context, runtime=first_runtime)
    replay = provision(context, runtime=first_runtime)

    assert replay['lifecycle_ref'] == first['lifecycle_ref']
    assert first['generation'] == 1
    assert first['status'] == WebLabInstance.Status.READY
    assert WebLabInstance.objects.count() == 1
    events = list(WebLabLifecycleEvent.objects.all())
    assert len(events) == 1
    assert events[0].sequence == 1
    assert events[0].event_type == WebLabLifecycleEvent.EventType.PROVISIONED
    assert len(events[0].entry_hash) == 64
    with pytest.raises(ValidationError):
        WebLabLifecycleEvent.objects.filter(pk=events[0].pk).update(details={'tampered': True})
    with pytest.raises(ValidationError):
        events[0].delete()


def test_provision_requires_current_asset_authorization(context):
    user, _project, asset, authorization, *_ = context
    AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=False, supersedes=authorization,
        target_snapshot='http://127.0.0.1:18081',
    )
    with pytest.raises(lifecycle.WebLabLifecycleAccessError, match='authorization'):
        provision(context)


def test_reset_requires_latest_cleaned_generation_and_increments_generation(context):
    first = provision(context)
    second_runtime = inspection(container_id='c' * 64)

    with pytest.raises(lifecycle.WebLabLifecycleError, match='explicitly supersede'):
        provision(context, key='p5-provision-2', runtime=second_runtime,
                  name='aegis-web-lab-111111111111')
    with pytest.raises(lifecycle.WebLabLifecycleError, match='cleaned prior generation'):
        provision(context, key='p5-provision-3', runtime=second_runtime,
                  supersedes=first['lifecycle_ref'], name='aegis-web-lab-222222222222')

    cleaned = lifecycle.mark_instance_cleaned(
        actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
        observed_container_id='b' * 64, reason='reset', idempotency_key='p5-clean-1',
    )
    assert cleaned['status'] == WebLabInstance.Status.CLEANED

    second = provision(
        context, key='p5-provision-4', runtime=second_runtime,
        supersedes=first['lifecycle_ref'], name='aegis-web-lab-333333333333',
    )
    assert second['generation'] == 2
    assert second['supersedes_ref'] == first['lifecycle_ref']

    lifecycle.mark_instance_cleaned(
        actor_id=str(context[0].id), instance_id=second['lifecycle_ref'],
        observed_container_id='c' * 64, reason='reset', idempotency_key='p5-clean-2',
    )
    with pytest.raises(lifecycle.WebLabLifecycleError, match='latest Web Lab generation'):
        provision(
            context, key='p5-provision-5', runtime=inspection(container_id='d' * 64),
            supersedes=first['lifecycle_ref'], name='aegis-web-lab-444444444444',
        )


def test_transition_reasons_are_state_bound(context):
    first = provision(context)
    with pytest.raises(lifecycle.WebLabLifecycleError, match='Expired cleanup'):
        lifecycle.mark_instance_cleaned(
            actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
            observed_container_id='b' * 64, reason='expired', idempotency_key='p5-bad-clean-expired',
        )
    with pytest.raises(lifecycle.WebLabLifecycleError, match='Failed cleanup'):
        lifecycle.mark_instance_cleaned(
            actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
            observed_container_id='b' * 64, reason='failed', idempotency_key='p5-bad-clean-failed',
        )

    failed = lifecycle.mark_instance_failed(
        actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
        observed_container_id='b' * 64, failure_code='runtime.exit', idempotency_key='p5-fail-1',
    )
    assert failed['status'] == WebLabInstance.Status.FAILED
    with pytest.raises(lifecycle.WebLabLifecycleError, match='Only a ready'):
        lifecycle.mark_instance_failed(
            actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
            observed_container_id='b' * 64, failure_code='runtime.again', idempotency_key='p5-fail-2',
        )
    cleaned = lifecycle.mark_instance_cleaned(
        actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
        observed_container_id='b' * 64, reason='failed', idempotency_key='p5-clean-failed',
    )
    assert cleaned['status'] == WebLabInstance.Status.CLEANED


def test_expiry_requires_boundary_before_expired_cleanup(context):
    first = provision(context)
    with pytest.raises(lifecycle.WebLabLifecycleError, match='expiry boundary'):
        lifecycle.mark_instance_expired(
            actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
            idempotency_key='p5-expire-early',
        )

    row = WebLabInstance.objects.get(pk=first['lifecycle_ref'])
    row.expires_at = timezone.now()
    row.save(update_fields=['expires_at', 'updated_at'])
    expired = lifecycle.mark_instance_expired(
        actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
        idempotency_key='p5-expire-1',
    )
    assert expired['status'] == WebLabInstance.Status.EXPIRED
    cleaned = lifecycle.mark_instance_cleaned(
        actor_id=str(context[0].id), instance_id=first['lifecycle_ref'],
        observed_container_id='b' * 64, reason='expired', idempotency_key='p5-clean-expired',
    )
    assert cleaned['status'] == WebLabInstance.Status.CLEANED


def test_chain_verification_and_postgres_trigger(context):
    first = provision(context)
    proof = lifecycle.verify_lifecycle_chain(
        actor_id=str(context[0].id), instance_id=first['lifecycle_ref'])
    assert proof['status'] == 'pass'
    assert proof['version'] == 1
    assert proof['event_count'] == 1
    assert len(proof['head_hash']) == 64

    if connection.vendor != 'postgresql':
        pytest.skip('Database-level immutability trigger is PostgreSQL-specific.')
    event = WebLabLifecycleEvent.objects.get(instance_id=first['lifecycle_ref'])
    with pytest.raises(DatabaseError):
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE enterprise_weblablifecycleevent "
                    "SET details = %s::jsonb WHERE id = %s",
                    ['{"tampered":true}', str(event.id)],
                )
    event.refresh_from_db()
    assert event.details.get('tampered') is None


def test_due_listing_is_bounded_and_only_returns_expired_ready_rows(context):
    first = provision(context)
    assert lifecycle.due_web_lab_instances(
        actor_id=str(context[0].id), project_id=str(context[1].id), limit=10) == []
    row = WebLabInstance.objects.get(pk=first['lifecycle_ref'])
    row.expires_at = timezone.now()
    row.save(update_fields=['expires_at', 'updated_at'])
    due = lifecycle.due_web_lab_instances(
        actor_id=str(context[0].id), project_id=str(context[1].id), limit=10)
    assert [item['lifecycle_ref'] for item in due] == [first['lifecycle_ref']]
    for limit in (0, 101):
        with pytest.raises(lifecycle.WebLabLifecycleError, match='due limit'):
            lifecycle.due_web_lab_instances(
                actor_id=str(context[0].id), project_id=str(context[1].id), limit=limit)


@pytest.mark.parametrize('role,allowed', [
    (OrganizationMembership.Role.OWNER, True),
    (OrganizationMembership.Role.ADMIN, True),
    (OrganizationMembership.Role.MANAGER, True),
    (OrganizationMembership.Role.ANALYST, False),
    (OrganizationMembership.Role.AUDITOR, False),
    (OrganizationMembership.Role.VIEWER, False),
])
def test_lab_management_and_inspector_use_same_tenant_roles(context, role, allowed):
    from django_project.system.credential_vault import CredentialVaultDenied
    from fastapi_app.services.lab_verification import record_runtime_inspection

    actor, _project, asset, _authorization, organization = context
    membership = OrganizationMembership.objects.get(organization=organization, user=actor)
    membership.role = role
    membership.save(update_fields=['role'])
    if allowed:
        scoped_actor, scoped_organization, scoped_asset = lifecycle._management_scope(
            actor_id=str(actor.pk), asset_id=str(asset.pk),
        )
        assert (scoped_actor.pk, scoped_organization.pk, scoped_asset.pk) == (
            actor.pk, organization.pk, asset.pk,
        )
        evidence = record_runtime_inspection(
            asset=asset, actor_id=str(actor.pk), inspection=inspection(),
        )
        assert evidence.asset_id == asset.pk
    else:
        with pytest.raises(lifecycle.WebLabLifecycleAccessError):
            lifecycle._management_scope(actor_id=str(actor.pk), asset_id=str(asset.pk))
        with pytest.raises(CredentialVaultDenied):
            record_runtime_inspection(
                asset=asset, actor_id=str(actor.pk), inspection=inspection(),
            )


def test_lab_management_and_inspector_reject_inactive_tenant_membership(context):
    from django_project.system.credential_vault import CredentialVaultDenied
    from fastapi_app.services.lab_verification import record_runtime_inspection

    actor, _project, asset, _authorization, organization = context
    membership = OrganizationMembership.objects.get(organization=organization, user=actor)
    membership.role = OrganizationMembership.Role.ADMIN
    membership.is_active = False
    membership.save(update_fields=['role', 'is_active'])
    with pytest.raises(lifecycle.WebLabLifecycleAccessError):
        lifecycle._management_scope(actor_id=str(actor.pk), asset_id=str(asset.pk))
    with pytest.raises(CredentialVaultDenied):
        record_runtime_inspection(
            asset=asset, actor_id=str(actor.pk), inspection=inspection(),
        )


def test_lab_tenant_management_does_not_cross_organization_boundary(context):
    from django_project.system.credential_vault import CredentialVaultDenied
    from fastapi_app.services.lab_verification import record_runtime_inspection

    actor, _project, _asset, _authorization, _organization = context
    other_owner = User.objects.create_user(
        email='other-lab-tenant@example.invalid', password='Test-Tenant-Password-123!',
    )
    other_organization = Organization.objects.create(
        name='Other Lab Tenant', slug='other-lab-tenant', owner=other_owner,
    )
    other_project = Project.objects.create(
        name='Other Tenant Project', slug='other-tenant-project', owner=actor,
    )
    other_asset = Asset.objects.create(
        project=other_project, owner=actor, name='Other Tenant Asset',
        slug='other-tenant-asset', type=Asset.Type.WEBSITE,
        configuration={'url': 'http://127.0.0.1:18081'},
    )
    TenantProject.objects.create(
        organization=other_organization, project=other_project,
    )
    assert not OrganizationMembership.objects.filter(
        organization=other_organization, user=actor, is_active=True,
    ).exists()
    with pytest.raises(lifecycle.WebLabLifecycleAccessError):
        lifecycle._management_scope(actor_id=str(actor.pk), asset_id=str(other_asset.pk))
    with pytest.raises(CredentialVaultDenied):
        record_runtime_inspection(
            asset=other_asset, actor_id=str(actor.pk), inspection=inspection(),
        )


def test_lab_admin_must_manage_the_project_linked_tenant_not_another_tenant(context):
    from django_project.projects.models import ProjectMembership
    from django_project.system.credential_vault import CredentialVaultDenied
    from fastapi_app.services.lab_verification import record_runtime_inspection

    owner, project, asset, _authorization, actual_tenant = context
    outsider = User.objects.create_user(
        email='web-lab-other-tenant-admin@example.invalid', password='test-only',
    )
    ProjectMembership.objects.create(
        project=project, user=outsider, role=ProjectMembership.Role.ADMIN,
    )
    unrelated_tenant = Organization.objects.create(
        name='Unrelated Web Lab Tenant', slug='unrelated-web-lab-tenant', owner=outsider,
    )
    OrganizationMembership.objects.create(
        organization=unrelated_tenant, user=outsider,
        role=OrganizationMembership.Role.ADMIN,
    )
    with pytest.raises(lifecycle.WebLabLifecycleAccessError):
        lifecycle._management_scope(actor_id=str(outsider.pk), asset_id=str(asset.pk))
    with pytest.raises(CredentialVaultDenied):
        record_runtime_inspection(
            asset=asset, actor_id=str(outsider.pk), inspection=inspection(),
        )

    OrganizationMembership.objects.create(
        organization=actual_tenant, user=outsider,
        role=OrganizationMembership.Role.ADMIN,
    )
    actor, tenant, scoped_asset = lifecycle._management_scope(
        actor_id=str(outsider.pk), asset_id=str(asset.pk),
    )
    assert actor.pk == outsider.pk and tenant.pk == actual_tenant.pk
    assert scoped_asset.pk == asset.pk
    evidence = record_runtime_inspection(
        asset=asset, actor_id=str(outsider.pk), inspection=inspection(),
    )
    assert evidence.asset_id == asset.pk
