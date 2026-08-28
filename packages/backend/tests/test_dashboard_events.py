import uuid
from unittest.mock import patch

import pytest
from django.db import transaction

from core.events import dashboard_group_name, publish_user_dashboard_event


@pytest.mark.django_db
def test_dashboard_group_name_is_stable():
    user_id = uuid.uuid4()
    assert dashboard_group_name(user_id) == f"dashboard_user_{user_id}"


@pytest.mark.django_db
def test_user_dashboard_event_is_published_after_commit():
    user_id = uuid.uuid4()
    project_id = uuid.uuid4()

    with patch("core.events._send") as send:
        with transaction.atomic():
            publish_user_dashboard_event(
                user_id=user_id,
                project_id=project_id,
                reason="scan.completed",
                entity="Scan",
                entity_id=uuid.uuid4(),
            )
            send.assert_not_called()

        send.assert_called_once()
        group_name, event = send.call_args.args
        assert group_name == dashboard_group_name(user_id)
        assert event["type"] == "dashboard.changed"
        assert event["reason"] == "scan.completed"
        assert event["project_id"] == str(project_id)
