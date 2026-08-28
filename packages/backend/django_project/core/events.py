"""Event-driven application events backed by the Django Channels Redis layer."""

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction

DASHBOARD_GROUP_PREFIX = "dashboard_user_"


def dashboard_group_name(user_id):
    return f"{DASHBOARD_GROUP_PREFIX}{user_id}"


def _recipient_ids(project):
    ids = set(project.members.values_list("id", flat=True))
    if project.owner_id:
        ids.add(project.owner_id)
    return ids


def publish_dashboard_event(*, project_id, reason, entity=None, entity_id=None):
    """Publish a small invalidation event after the surrounding DB transaction commits.

    The event deliberately contains no sensitive entity data. Consumers re-read the
    tenant-scoped dashboard snapshot through the existing authorization boundary.
    """
    from projects.models import Project

    def _publish():
        try:
            project = Project.objects.get(pk=project_id)
        except Project.DoesNotExist:
            return

        channel_layer = get_channel_layer()
        if channel_layer is None:
            return

        event = {
            "type": "dashboard.changed",
            "reason": reason,
            "project_id": str(project_id),
            "entity": entity,
            "entity_id": str(entity_id) if entity_id else None,
        }
        for user_id in _recipient_ids(project):
            async_to_sync(channel_layer.group_send)(dashboard_group_name(user_id), event)

    transaction.on_commit(_publish)
