"""Event-driven application events backed by the Django Channels Redis layer."""

import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.db import transaction

logger = logging.getLogger(__name__)
DASHBOARD_GROUP_PREFIX = "dashboard_user_"


def dashboard_group_name(user_id):
    return f"{DASHBOARD_GROUP_PREFIX}{user_id}"


def _send(group_name, event):
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    try:
        async_to_sync(channel_layer.group_send)(group_name, event)
    except Exception:
        # Redis/Channels is an availability enhancement for the dashboard. A
        # broker outage must never turn a committed domain write into a 500.
        logger.exception("Failed to publish dashboard event to %s", group_name)


def _event(*, project_id, reason, entity=None, entity_id=None):
    return {
        "type": "dashboard.changed",
        "reason": reason,
        "project_id": str(project_id),
        "entity": entity,
        "entity_id": str(entity_id) if entity_id else None,
    }


def publish_user_dashboard_event(*, user_id, project_id, reason, entity=None, entity_id=None):
    """Publish an event to one user's dashboard group after commit."""
    event = _event(
        project_id=project_id,
        reason=reason,
        entity=entity,
        entity_id=entity_id,
    )
    transaction.on_commit(lambda: _send(dashboard_group_name(user_id), event))


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
            recipients = _recipient_ids(project)
        except Project.DoesNotExist:
            return
        except Exception:
            logger.exception("Failed to resolve dashboard event recipients for %s", project_id)
            return

        event = _event(
            project_id=project_id,
            reason=reason,
            entity=entity,
            entity_id=entity_id,
        )
        for user_id in recipients:
            _send(dashboard_group_name(user_id), event)

    transaction.on_commit(_publish)
