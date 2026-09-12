from __future__ import annotations

import pytest

from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution
from django_project.users.models import User
from fastapi_app.tasks.reliability_probe import (
    PROBE_ENGINE,
    PROBE_SOURCE,
    scanner_worker_loss_probe,
)


def _scan() -> Scan:
    user = User.objects.create_user(
        email="worker-loss-probe@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(
        name="Worker loss reliability",
        slug="worker-loss-reliability",
        owner=user,
    )
    return Scan.objects.create(
        project=project,
        name="Scanner worker loss probe",
        scan_type=Scan.Type.IP,
        status=Scan.Status.QUEUED,
        engines=[PROBE_ENGINE],
        initiated_by=user,
    )


@pytest.mark.django_db
def test_probe_fails_closed_when_not_explicitly_enabled(monkeypatch):
    monkeypatch.delenv("AEGIS_RELIABILITY_PROBE_ENABLED", raising=False)
    scan = _scan()

    with pytest.raises(RuntimeError, match="reliability probe is disabled"):
        scanner_worker_loss_probe.run(str(scan.id))

    scan.refresh_from_db()
    assert scan.status == Scan.Status.QUEUED
    assert not ScanEngineExecution.objects.filter(scan=scan).exists()
    assert not Evidence.objects.filter(scan=scan).exists()


@pytest.mark.django_db
def test_probe_completes_one_durable_operation(monkeypatch):
    monkeypatch.setenv("AEGIS_RELIABILITY_PROBE_ENABLED", "1")
    monkeypatch.setenv("AEGIS_RELIABILITY_PROBE_HOLD_SECONDS", "0")
    scan = _scan()

    result = scanner_worker_loss_probe.run(str(scan.id))
    terminal = scanner_worker_loss_probe.run(str(scan.id))

    scan.refresh_from_db()
    execution = ScanEngineExecution.objects.get(scan=scan, engine__name=PROBE_ENGINE)
    evidence = Evidence.objects.get(scan=scan, source=PROBE_SOURCE)

    assert result["status"] == Scan.Status.COMPLETED
    assert result["attempts"] == 1
    assert terminal["terminal"] is True
    assert terminal["attempts"] == 1
    assert scan.status == Scan.Status.COMPLETED
    assert execution.status == ScanEngineExecution.ExecutionStatus.COMPLETED
    assert execution.result_data["probe_attempts"] == 1
    assert Evidence.objects.filter(scan=scan, source=PROBE_SOURCE).count() == 1
    assert len(evidence.sha256) == 64


@pytest.mark.django_db
def test_redelivery_recovers_stale_running_state_without_duplicates(monkeypatch):
    monkeypatch.setenv("AEGIS_RELIABILITY_PROBE_ENABLED", "true")
    monkeypatch.setenv("AEGIS_RELIABILITY_PROBE_HOLD_SECONDS", "0")
    scan = _scan()
    scan.status = Scan.Status.RUNNING
    scan.progress = 40
    scan.save(update_fields=["status", "progress", "updated_at"])

    engine = ScanEngine.objects.create(
        name=PROBE_ENGINE,
        display_name="Scanner Reliability Probe",
        category=ScanEngine.EngineCategory.CONTROL,
        version="1.0",
        status=ScanEngine.EngineStatus.ACTIVE,
        is_core=False,
        timeout=300,
    )
    execution = ScanEngineExecution.objects.create(
        scan=scan,
        engine=engine,
        status=ScanEngineExecution.ExecutionStatus.RUNNING,
        progress=40,
        result_data={"probe_attempts": 1, "task_id": "same-redelivered-message"},
    )

    recovered = scanner_worker_loss_probe.run(str(scan.id))
    duplicate = scanner_worker_loss_probe.run(str(scan.id))

    scan.refresh_from_db()
    execution.refresh_from_db()

    assert recovered["status"] == Scan.Status.COMPLETED
    assert recovered["attempts"] == 2
    assert recovered["redelivered"] is True
    assert duplicate["terminal"] is True
    assert duplicate["attempts"] == 2
    assert scan.status == Scan.Status.COMPLETED
    assert execution.status == ScanEngineExecution.ExecutionStatus.COMPLETED
    assert execution.result_data["probe_attempts"] == 2
    assert execution.result_data["completed_after_redelivery"] is True
    assert ScanEngineExecution.objects.filter(scan=scan, engine=engine).count() == 1
    assert Evidence.objects.filter(scan=scan, source=PROBE_SOURCE).count() == 1
