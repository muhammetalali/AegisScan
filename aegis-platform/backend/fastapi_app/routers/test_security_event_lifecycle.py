from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from asgiref.sync import async_to_sync
from django.db import close_old_connections, connection
from fastapi import HTTPException
from pydantic import ValidationError

from django_project.audit.models import AuditLog, SecurityEvent
from django_project.users.models import Permission, User, UserRole
from enterprise.models import Notification, Organization, OrganizationMembership
from fastapi_app.routers.audit import SecurityEventTransition, _security_event, _security_events, _transition_security_event


pytestmark = pytest.mark.django_db(transaction=True)


def _user(email: str, role: str) -> User:
    return User.objects.create_user(email=email, password='Strong-Test-Password-123!', role=role)


def _event_for_organization(organization: Organization, recipient: User) -> SecurityEvent:
    target = _user('event-target@example.invalid', UserRole.VIEWER)
    event = SecurityEvent.objects.create(
        event_type=SecurityEvent.EventType.BRUTE_FORCE,
        severity=SecurityEvent.Severity.HIGH,
        title='Repeated authentication failures detected',
        description='Threshold exceeded',
        source_ip='203.0.113.51',
        target_user=target,
        indicators=['ip:203.0.113.51'],
        raw_data={'observed_failures': 5},
    )
    Notification.objects.create(
        organization=organization,user=recipient,source_security_event=event,
        channel=Notification.Channel.IN_APP,event_type=event.event_type,
    )
    return event


def test_security_event_permissions_match_operational_roles():
    manager = _user('permission-manager@example.invalid', UserRole.SECURITY_MANAGER)
    analyst = _user('permission-analyst@example.invalid', UserRole.SECURITY_ANALYST)
    auditor = _user('permission-auditor@example.invalid', UserRole.AUDITOR)
    viewer = _user('permission-viewer@example.invalid', UserRole.VIEWER)

    assert manager.has_all_permissions(Permission.SECURITY_EVENT_READ, Permission.SECURITY_EVENT_RESPOND)
    assert analyst.has_all_permissions(Permission.SECURITY_EVENT_READ, Permission.SECURITY_EVENT_RESPOND)
    assert auditor.has_permission(Permission.SECURITY_EVENT_READ)
    assert not auditor.has_permission(Permission.SECURITY_EVENT_RESPOND)
    assert not viewer.has_permission(Permission.SECURITY_EVENT_READ)


def test_security_event_transition_rejects_unknown_contract_fields():
    with pytest.raises(ValidationError):
        SecurityEventTransition.model_validate({'status': 'investigating', 'synthetic_success': True})


def test_security_event_visibility_is_tenant_scoped():
    owner = _user('event-owner@example.invalid', UserRole.ADMIN)
    analyst = _user('event-analyst@example.invalid', UserRole.SECURITY_ANALYST)
    outsider = _user('event-outsider@example.invalid', UserRole.SECURITY_ANALYST)
    organization = Organization.objects.create(name='Event Org', slug='event-org', owner=owner)
    OrganizationMembership.objects.create(organization=organization,user=analyst,role=OrganizationMembership.Role.ANALYST)
    event = _event_for_organization(organization, owner)

    visible = async_to_sync(_security_events)(str(analyst.id), 50, 0, None, None)
    hidden = async_to_sync(_security_events)(str(outsider.id), 50, 0, None, None)

    assert visible['total'] == 1
    assert visible['items'][0]['id'] == str(event.id)
    assert hidden == {'items': [], 'total': 0, 'limit': 50, 'offset': 0}
    with pytest.raises(HTTPException) as inaccessible:
        async_to_sync(_security_event)(str(outsider.id), str(event.id))
    assert inaccessible.value.status_code == 404


def test_security_event_lifecycle_is_monotonic_and_hash_audited():
    owner = _user('lifecycle-owner@example.invalid', UserRole.ADMIN)
    analyst = _user('lifecycle-analyst@example.invalid', UserRole.SECURITY_ANALYST)
    organization = Organization.objects.create(name='Lifecycle Org', slug='lifecycle-org', owner=owner)
    OrganizationMembership.objects.create(organization=organization,user=analyst,role=OrganizationMembership.Role.ANALYST)
    event = _event_for_organization(organization, owner)

    investigating = async_to_sync(_transition_security_event)(
        str(analyst.id), str(event.id), SecurityEventTransition(status='investigating'),
    )
    assert investigating['status'] == SecurityEvent.Status.INVESTIGATING
    assert investigating['assigned_to_id'] == str(analyst.id)

    with pytest.raises(HTTPException) as missing_notes:
        async_to_sync(_transition_security_event)(
            str(analyst.id), str(event.id), SecurityEventTransition(status='resolved'),
        )
    assert missing_notes.value.status_code == 422

    resolved = async_to_sync(_transition_security_event)(
        str(analyst.id), str(event.id),
        SecurityEventTransition(status='resolved', resolution_notes='Blocked source and reset the targeted account.'),
    )
    assert resolved['status'] == SecurityEvent.Status.RESOLVED
    assert resolved['resolved_by_id'] == str(analyst.id)
    assert resolved['resolved_at'] is not None

    with pytest.raises(HTTPException) as terminal_reopen:
        async_to_sync(_transition_security_event)(
            str(analyst.id), str(event.id), SecurityEventTransition(status='investigating'),
        )
    assert terminal_reopen.value.status_code == 409
    audits = list(AuditLog.objects.filter(action=AuditLog.Action.SECURITY_EVENT_STATUS_CHANGE).order_by('chain_index'))
    assert [entry.changes['status'] for entry in audits] == [
        {'from':'new','to':'investigating'}, {'from':'investigating','to':'resolved'},
    ]
    assert all(entry.entry_hash and len(entry.entry_hash) == 64 for entry in audits)
    assert all(entry.resource_id == str(event.id) for entry in audits)


def test_cross_tenant_transition_returns_not_found():
    owner = _user('cross-owner@example.invalid', UserRole.ADMIN)
    outsider = _user('cross-outsider@example.invalid', UserRole.SECURITY_ANALYST)
    organization = Organization.objects.create(name='Cross Tenant Org', slug='cross-event-org', owner=owner)
    event = _event_for_organization(organization, owner)

    with pytest.raises(HTTPException) as inaccessible:
        async_to_sync(_transition_security_event)(
            str(outsider.id), str(event.id), SecurityEventTransition(status='investigating'),
        )
    assert inaccessible.value.status_code == 404
    event.refresh_from_db()
    assert event.status == SecurityEvent.Status.NEW
    assert not AuditLog.objects.filter(resource_id=str(event.id)).exists()


def test_concurrent_responders_cannot_apply_two_first_transitions():
    if connection.vendor != 'postgresql':
        pytest.skip('Concurrent lifecycle proof requires PostgreSQL row locks')
    owner = _user('concurrent-event-owner@example.invalid', UserRole.ADMIN)
    analyst = _user('concurrent-event-analyst@example.invalid', UserRole.SECURITY_ANALYST)
    organization = Organization.objects.create(name='Concurrent Event Org', slug='concurrent-event-org', owner=owner)
    OrganizationMembership.objects.create(organization=organization,user=analyst,role=OrganizationMembership.Role.ANALYST)
    event = _event_for_organization(organization, owner)

    def transition():
        close_old_connections()
        try:
            return async_to_sync(_transition_security_event)(
                str(analyst.id), str(event.id), SecurityEventTransition(status='investigating'),
            )
        except HTTPException as exc:
            return exc.status_code
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: transition(), range(2)))

    assert sorted(409 if result == 409 else 200 for result in results) == [200, 409]
    event.refresh_from_db()
    assert event.status == SecurityEvent.Status.INVESTIGATING
    assert AuditLog.objects.filter(action=AuditLog.Action.SECURITY_EVENT_STATUS_CHANGE,resource_id=str(event.id)).count() == 1
