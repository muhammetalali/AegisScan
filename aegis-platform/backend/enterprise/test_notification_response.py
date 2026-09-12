from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import close_old_connections, connection
from django.utils import timezone
from fastapi import HTTPException

from django_project.projects.models import Project
from django_project.users.auth_audit import record_login_event
from django_project.users.models import User
from enterprise.models import Notification, Organization, OrganizationMembership
from enterprise.tasks import dispatch_notification_deliveries, send_notification
from fastapi_app.routers.enterprise_extra import NotificationCreate, _create_notification


pytestmark = pytest.mark.django_db(transaction=True)


class _Request:
    META = {'REMOTE_ADDR': '203.0.113.42', 'HTTP_USER_AGENT': 'notification-response-test'}


class _ChannelLayer:
    def __init__(self):
        self.calls = []

    async def group_send(self, group, event):
        self.calls.append((group, event))


def _organization(owner: User, slug: str = 'notification-response-org') -> Organization:
    organization = Organization.objects.create(name='Notification Response Org', slug=slug, owner=owner)
    OrganizationMembership.objects.create(
        organization=organization, user=owner, role=OrganizationMembership.Role.OWNER,
    )
    return organization


def test_brute_force_detection_persists_tenant_scoped_response_notifications(monkeypatch, settings):
    settings.AUTH_BRUTE_FORCE_THRESHOLD = 3
    settings.AUTH_BRUTE_FORCE_WINDOW_SECONDS = 600
    owner = User.objects.create_user(email='response-owner@example.invalid', password='Strong-Test-Password-123!')
    manager = User.objects.create_user(email='response-manager@example.invalid', password='Strong-Test-Password-123!')
    victim = User.objects.create_user(email='response-victim@example.invalid', password='Strong-Test-Password-123!')
    outsider = User.objects.create_user(email='response-outsider@example.invalid', password='Strong-Test-Password-123!')
    organization = _organization(owner)
    OrganizationMembership.objects.create(organization=organization, user=manager, role=OrganizationMembership.Role.MANAGER)
    OrganizationMembership.objects.create(organization=organization, user=victim, role=OrganizationMembership.Role.VIEWER)
    queued = []
    monkeypatch.setattr(send_notification, 'delay', lambda notification_id: queued.append(notification_id))

    for _ in range(3):
        record_login_event(_Request(), email=victim.email, success=False, failure_reason='invalid_credentials')

    notifications = list(Notification.objects.select_related('source_security_event').order_by('user_id'))
    assert {item.user_id for item in notifications} == {owner.id, manager.id}
    assert all(item.organization_id == organization.id for item in notifications)
    assert all(item.channel == Notification.Channel.IN_APP for item in notifications)
    assert all(item.source_security_event.target_user_id == victim.id for item in notifications)
    assert all(item.payload['observed_failures'] == 3 for item in notifications)
    assert Notification.objects.filter(user=outsider).count() == 0
    assert sorted(queued) == sorted(str(item.id) for item in notifications)


def test_in_app_delivery_is_terminal_and_replayed_without_duplicate_send(monkeypatch):
    owner = User.objects.create_user(email='delivery-owner@example.invalid', password='Strong-Test-Password-123!')
    organization = _organization(owner, 'delivery-org')
    item = Notification.objects.create(
        organization=organization, user=owner, channel=Notification.Channel.IN_APP,
        event_type='brute_force', payload={'title':'Attack detected','message':'Threshold exceeded','severity':'high'},
    )
    layer = _ChannelLayer()
    monkeypatch.setattr('enterprise.tasks.get_channel_layer', lambda: layer)

    first = send_notification.run(str(item.id))
    second = send_notification.run(str(item.id))

    item.refresh_from_db()
    assert first['replayed'] is False
    assert second == {'status':'sent','notification_id':str(item.id),'replayed':True}
    assert item.status == Notification.Status.SENT
    assert item.attempts == 1
    assert len(layer.calls) == 1
    assert layer.calls[0][0] == f'user_{owner.id}'


def test_notification_creation_enforces_tenant_recipient_and_forbids_direct_url(monkeypatch):
    owner = User.objects.create_user(email='tenant-owner@example.invalid', password='Strong-Test-Password-123!')
    outsider = User.objects.create_user(email='tenant-outsider@example.invalid', password='Strong-Test-Password-123!')
    organization = _organization(owner, 'tenant-notification-org')
    project = Project.objects.create(name='Notification Tenant', slug='notification-tenant', owner=owner)
    monkeypatch.setattr(send_notification, 'delay', lambda notification_id: None)

    with pytest.raises(HTTPException) as cross_tenant:
        _create_notification(organization, NotificationCreate(
            project_id=project.id, user_id=outsider.id, channel='in_app', event_type='test', payload={},
        ), str(owner.id))
    assert cross_tenant.value.status_code == 404

    with pytest.raises(HTTPException) as direct_url:
        _create_notification(organization, NotificationCreate(
            project_id=project.id, channel='webhook', event_type='test', payload={'url':'http://169.254.169.254/latest/meta-data'},
        ), str(owner.id))
    assert direct_url.value.status_code == 422
    assert Notification.objects.count() == 0


def test_delivery_outbox_recovers_stale_claim_but_not_active_claim(monkeypatch):
    owner = User.objects.create_user(email='outbox-owner@example.invalid', password='Strong-Test-Password-123!')
    organization = _organization(owner, 'outbox-org')
    stale = Notification.objects.create(organization=organization,user=owner,channel='in_app',event_type='stale',status=Notification.Status.SENDING,attempts=1)
    active = Notification.objects.create(organization=organization,user=owner,channel='in_app',event_type='active',status=Notification.Status.SENDING,attempts=1)
    Notification.objects.filter(pk=stale.pk).update(updated_at=timezone.now()-timedelta(minutes=11))
    queued = []
    monkeypatch.setattr(send_notification, 'delay', lambda notification_id: queued.append(notification_id))

    result = dispatch_notification_deliveries()

    assert result['queued'] == 1
    assert queued == [str(stale.id)]
    assert str(active.id) not in queued


def test_concurrent_delivery_claim_sends_once_on_postgresql(monkeypatch):
    if connection.vendor != 'postgresql':
        pytest.skip('Concurrent row-lock proof requires PostgreSQL')
    owner = User.objects.create_user(email='concurrent-delivery@example.invalid', password='Strong-Test-Password-123!')
    organization = _organization(owner, 'concurrent-delivery-org')
    item = Notification.objects.create(organization=organization,user=owner,channel='in_app',event_type='concurrent')
    layer = _ChannelLayer()
    monkeypatch.setattr('enterprise.tasks.get_channel_layer', lambda: layer)

    def deliver():
        close_old_connections()
        try:
            return send_notification.run(str(item.id))
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: deliver(), range(2)))

    item.refresh_from_db()
    assert item.status == Notification.Status.SENT
    assert item.attempts == 1
    assert len(layer.calls) == 1
    assert sorted(result['replayed'] for result in results) == [False, True]


def test_in_app_delivery_reaches_real_channel_layer_on_postgresql():
    if connection.vendor != 'postgresql':
        pytest.skip('Real Redis channel-layer proof runs with the PostgreSQL/Redis CI services')
    owner = User.objects.create_user(email='realtime-delivery@example.invalid', password='Strong-Test-Password-123!')
    organization = _organization(owner, 'realtime-delivery-org')
    item = Notification.objects.create(
        organization=organization,user=owner,channel='in_app',event_type='brute_force',
        payload={'title':'Attack detected','message':'Threshold exceeded','severity':'high','action_url':'/audit'},
    )
    layer = get_channel_layer()
    channel = async_to_sync(layer.new_channel)('notification-response.')
    async_to_sync(layer.group_add)(f'user_{owner.id}', channel)
    try:
        result = send_notification.run(str(item.id))
        event = async_to_sync(layer.receive)(channel)
    finally:
        async_to_sync(layer.group_discard)(f'user_{owner.id}', channel)

    assert result['status'] == 'sent'
    assert event['type'] == 'notification'
    assert event['id'] == str(item.id)
    assert event['title'] == 'Attack detected'
    assert event['action_url'] == '/audit'
