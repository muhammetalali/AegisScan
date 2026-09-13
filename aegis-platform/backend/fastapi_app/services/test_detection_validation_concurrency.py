from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import close_old_connections

from enterprise.detection_models import DetectionEvent, DetectionValidation
from fastapi_app.services.detection_engineering import validate_revision
from fastapi_app.services.test_detection_engineering import _revision, _telemetry


pytestmark = pytest.mark.django_db(transaction=True)


def test_validation_exact_replay_is_serialized_on_postgresql(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _revision(user, project, finding, evidence).revision
    barrier = threading.Barrier(2)

    def worker():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return validate_revision(
                revision_id=str(revision.id),
                project_id=str(project.id),
                user_id=str(user.id),
                telemetry=_telemetry(),
                minimum_matches=1,
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]

    assert sorted(result.replayed for result in results) == [False, True]
    assert results[0].validation.id == results[1].validation.id
    assert DetectionValidation.objects.filter(revision=revision).count() == 1
    assert DetectionEvent.objects.filter(rule=revision.rule, event_type='validation.completed').count() == 1
