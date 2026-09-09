from __future__ import annotations

from django.db import transaction

from django_project.audit.models import SecurityEvent

from .models import Notification, Organization, OrganizationMembership


_SECURITY_RECIPIENT_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
}


def create_security_event_notifications(event: SecurityEvent) -> list[Notification]:
    """Persist tenant-scoped in-app response records for an attributable event."""
    if event.target_user_id is None:
        return []

    organization_ids = list(
        OrganizationMembership.objects.filter(
            user_id=event.target_user_id,
            is_active=True,
            organization__is_active=True,
        ).values_list('organization_id', flat=True)
    )
    if not organization_ids:
        return []

    organizations = Organization.objects.filter(id__in=organization_ids).select_related('owner').only('id', 'owner_id', 'owner__is_active')
    recipients_by_organization: dict[object, set[object]] = {
        organization.id: ({organization.owner_id} if organization.owner.is_active else set())
        for organization in organizations
    }
    memberships = OrganizationMembership.objects.filter(
        organization_id__in=organization_ids,
        role__in=_SECURITY_RECIPIENT_ROLES,
        is_active=True,
        user__is_active=True,
    ).values_list('organization_id', 'user_id')
    for organization_id, user_id in memberships:
        recipients_by_organization.setdefault(organization_id, set()).add(user_id)

    created: list[Notification] = []
    for organization_id, user_ids in recipients_by_organization.items():
        for user_id in user_ids:
            notification, was_created = Notification.objects.get_or_create(
                source_security_event=event,
                user_id=user_id,
                channel=Notification.Channel.IN_APP,
                defaults={
                    'organization_id': organization_id,
                    'event_type': event.event_type,
                    'payload': {
                        'title': event.title,
                        'message': event.description,
                        'severity': event.severity,
                        'security_event_id': str(event.id),
                        'source_ip': str(event.source_ip) if event.source_ip else None,
                        'target_user_id': str(event.target_user_id),
                        'observed_failures': event.raw_data.get('observed_failures'),
                        'action_url': '/audit',
                    },
                },
            )
            if was_created:
                created.append(notification)

    if created:
        notification_ids = tuple(str(notification.id) for notification in created)

        def enqueue() -> None:
            from .tasks import send_notification

            for notification_id in notification_ids:
                send_notification.delay(notification_id)

        transaction.on_commit(enqueue, robust=True)
    return created
