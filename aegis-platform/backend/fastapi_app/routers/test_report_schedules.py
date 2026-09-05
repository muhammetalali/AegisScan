import hashlib
from datetime import timedelta
from pathlib import Path

from asgiref.sync import async_to_sync
import pytest
from asgiref.sync import sync_to_async
from django.db import connections
from django.core import mail
from django.core.files.base import ContentFile
from django.core.signing import dumps
from django.utils import timezone as django_timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient

from django_celery_beat.models import PeriodicTask

from django_project.projects.models import Project
from django_project.users.models import User, UserRole
from django_project.audit.models import DataExport
from enterprise.models import ReportRecipientDelivery, ReportSchedule, ReportScheduleExecution
from enterprise.tasks import deliver_scheduled_report, dispatch_due_schedules, dispatch_report_deliveries, execute_report_schedule, expire_report_exports
from fastapi import HTTPException
from fastapi_app.routers import reports as reports_router
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.routers.reports import (
    ReportScheduleCreate,
    ReportScheduleUpdate,
    _create_report_schedules,
    _delete_report_schedule,
    _get_report_schedule,
    _list_report_schedules,
    _list_report_schedule_executions,
    _list_report_recipient_deliveries,
    _update_report_schedule,
    download_report,
    download_shared_report,
    router,
    share_report,
)
from starlette.routing import Match


@pytest.fixture
def report_projects(db):
    owner = User.objects.create_user(
        email="report-owner@example.invalid",
        password="Strong-Test-Password-123!",
    )
    outsider = User.objects.create_user(
        email="report-outsider@example.invalid",
        password="Strong-Test-Password-123!",
    )
    project = Project.objects.create(name="Report Reality", slug="report-reality", owner=owner)
    other_project = Project.objects.create(name="Other Reports", slug="other-reports", owner=outsider)
    return owner, outsider, project, other_project


@pytest.mark.django_db
def test_report_schedule_persists_each_format_and_periodic_task(report_projects):
    owner, _, project, _ = report_projects
    body = ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=["Security@example.com", "security@example.com"],
        formats=["pdf", "json", "pdf"],
    )

    rows = async_to_sync(_create_report_schedules)(body, str(owner.id))

    assert [row.format for row in rows] == ["pdf", "json"]
    assert ReportSchedule.objects.filter(project=project, created_by=owner).count() == 2
    assert all(row.recipients == ["security@example.com"] for row in rows)
    for row in rows:
        task = PeriodicTask.objects.get(name=f"aegis-report:{row.id}")
        assert task.task == "enterprise.execute_report_schedule"
        assert str(row.id) in task.kwargs
        assert task.enabled is True


@pytest.mark.django_db
def test_report_schedule_validation_is_atomic(report_projects):
    owner, _, project, _ = report_projects
    body = ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=["not-an-email"], formats=["pdf", "json"],
    )

    with pytest.raises(HTTPException) as exc:
        async_to_sync(_create_report_schedules)(body, str(owner.id))

    assert exc.value.status_code == 400
    assert ReportSchedule.objects.count() == 0
    assert PeriodicTask.objects.filter(name__startswith="aegis-report:").count() == 0


@pytest.mark.django_db
def test_report_schedule_listing_is_user_and_project_scoped(report_projects):
    owner, outsider, project, other_project = report_projects
    for user, target in ((owner, project), (outsider, other_project)):
        async_to_sync(_create_report_schedules)(ReportScheduleCreate(
            project_id=str(target.id), template_id="findings", frequency="weekly",
            recipients=[user.email], formats=["csv"],
        ), str(user.id))

    rows = async_to_sync(_list_report_schedules)(str(owner.id), str(project.id))

    assert len(rows) == 1
    assert rows[0].project_id == project.id
    assert rows[0].created_by_id == owner.id


@pytest.mark.parametrize("path", ["/schedules", "/templates"])
def test_static_report_routes_are_not_shadowed_by_report_id(path):
    scope = {
        "type": "http", "path": path, "method": "GET", "root_path": "",
        "scheme": "http", "query_string": b"", "headers": [],
        "server": ("test", 80), "client": ("test", 1), "http_version": "1.1",
    }

    first_full_match = next(route for route in router.routes if route.matches(scope)[0] == Match.FULL)

    assert first_full_match.path == path


@pytest.mark.django_db
def test_report_schedule_executes_real_report_and_advances_schedule(report_projects, settings, tmp_path):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    previous_next_run = schedule.next_run

    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-delivery-1")

    schedule.refresh_from_db()
    report = DataExport.objects.get(id=result["report_id"])
    assert result["status"] == "completed"
    assert report.status == DataExport.Status.COMPLETED
    assert report.resource_type == "project_report"
    assert report.file_size > 0
    assert report.file.name.endswith(".json")
    assert schedule.last_run is not None
    assert schedule.next_run > previous_next_run
    execution = ReportScheduleExecution.objects.get(delivery_id="report-delivery-1")
    assert execution.status == ReportScheduleExecution.Status.COMPLETED
    assert execution.report_id == report.id
    assert execution.attempts == 1
    assert ReportRecipientDelivery.objects.filter(execution=execution).count() == 1

    replay = execute_report_schedule.run(str(schedule.id), delivery_id="report-delivery-1")

    assert replay == {
        "status": "completed", "schedule_id": str(schedule.id),
        "report_id": str(report.id), "replayed": True,
    }
    assert DataExport.objects.filter(resource_type="project_report").count() == 1
    execution.refresh_from_db()
    assert execution.attempts == 1


@pytest.mark.django_db
def test_recipient_outbox_sends_real_attachment_and_replays_without_duplicate(report_projects, settings, tmp_path):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-email-delivery")
    delivery = ReportRecipientDelivery.objects.get(execution_id=result["execution_id"])

    sent = deliver_scheduled_report.run(str(delivery.id))

    delivery.refresh_from_db()
    assert sent["status"] == "sent"
    assert sent["replayed"] is False
    assert delivery.status == ReportRecipientDelivery.Status.SENT
    assert delivery.attempts == 1
    assert delivery.sent_at is not None
    assert len(delivery.artifact_sha256) == 64
    assert len(mail.outbox) == 1
    assert mail.outbox[0].to == [owner.email]
    assert mail.outbox[0].extra_headers["Message-ID"] == delivery.message_id
    assert len(mail.outbox[0].attachments) == 1
    assert mail.outbox[0].attachments[0][0].endswith(".json")
    assert hashlib.sha256(mail.outbox[0].attachments[0][1]).hexdigest() == delivery.artifact_sha256
    assert sent["artifact_sha256"] == delivery.artifact_sha256

    replay = deliver_scheduled_report.run(str(delivery.id))

    assert replay["replayed"] is True
    assert len(mail.outbox) == 1
    delivery.refresh_from_db()
    assert delivery.attempts == 1


@pytest.mark.django_db
def test_report_delivery_dispatcher_queues_only_retryable_outbox_rows(report_projects, settings, tmp_path, monkeypatch):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email, "soc@example.com"], formats=["json"],
    ), str(owner.id))[0]
    execute_report_schedule.run(str(schedule.id), delivery_id="report-outbox-dispatch")
    queued=[]
    monkeypatch.setattr(deliver_scheduled_report, "delay", lambda delivery_id: queued.append(delivery_id))

    result = dispatch_report_deliveries.run()

    assert result["queued"] == 2
    assert sorted(queued) == sorted(result["delivery_ids"])


@pytest.mark.django_db
def test_stale_sending_delivery_is_recovered_and_sent(report_projects, settings, tmp_path):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-stale-delivery")
    delivery = ReportRecipientDelivery.objects.get(execution_id=result["execution_id"])
    ReportRecipientDelivery.objects.filter(pk=delivery.id).update(
        status=ReportRecipientDelivery.Status.SENDING, attempts=1,
        updated_at=django_timezone.now()-timedelta(minutes=11),
    )

    sent = deliver_scheduled_report.run(str(delivery.id))

    delivery.refresh_from_db()
    assert sent["status"] == "sent"
    assert delivery.status == ReportRecipientDelivery.Status.SENT
    assert delivery.attempts == 2
    assert len(mail.outbox) == 1


@pytest.mark.django_db
def test_recipient_delivery_history_is_schedule_owner_scoped(report_projects, settings, tmp_path):
    owner, outsider, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-history-delivery")

    rows = async_to_sync(_list_report_recipient_deliveries)(
        str(schedule.id), result["execution_id"], str(owner.id),
    )
    assert len(rows) == 1
    with pytest.raises(HTTPException) as exc:
        async_to_sync(_list_report_recipient_deliveries)(
            str(schedule.id), result["execution_id"], str(outsider.id),
        )
    assert exc.value.status_code == 404


@pytest.mark.django_db
def test_due_dispatcher_does_not_duplicate_beat_managed_reports(report_projects, monkeypatch):
    owner, _, project, _ = report_projects
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    ReportSchedule.objects.filter(pk=schedule.id).update(next_run="2000-01-01T00:00:00Z")
    monkeypatch.setattr(execute_report_schedule, "delay", lambda *_args, **_kwargs: pytest.fail(
        "beat-managed report schedules must not also be queued by the due dispatcher"
    ))

    result = dispatch_due_schedules.run()

    assert result == {"queued": 0, "reports": 0, "assurance": 0}


@pytest.mark.django_db
def test_failed_report_delivery_reuses_durable_execution_on_retry(report_projects, settings, tmp_path, monkeypatch):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    real_build_payload = reports_router._build_payload

    async def fail_build(*_args, **_kwargs):
        raise RuntimeError("deterministic report build failure")

    monkeypatch.setattr(reports_router, "_build_payload", fail_build)
    with pytest.raises(RuntimeError, match="deterministic report build failure"):
        execute_report_schedule.run(str(schedule.id), delivery_id="report-delivery-retry")

    execution = ReportScheduleExecution.objects.get(delivery_id="report-delivery-retry")
    assert execution.status == ReportScheduleExecution.Status.FAILED
    assert execution.attempts == 1
    assert execution.report_id is None

    monkeypatch.setattr(reports_router, "_build_payload", real_build_payload)
    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-delivery-retry")

    execution.refresh_from_db()
    assert result["status"] == "completed"
    assert result["replayed"] is False
    assert execution.status == ReportScheduleExecution.Status.COMPLETED
    assert execution.attempts == 2
    assert DataExport.objects.filter(resource_type="project_report").count() == 1


@pytest.mark.django_db
def test_report_schedule_update_synchronizes_celery_beat(report_projects):
    owner, _, project, _ = report_projects
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="findings", frequency="daily",
        recipients=[owner.email], formats=["pdf"],
    ), str(owner.id))[0]

    updated = async_to_sync(_update_report_schedule)(str(schedule.id), str(owner.id), ReportScheduleUpdate(
        title="Weekly risk review", frequency="weekly",
        recipients=["SOC@example.com"], enabled=False,
    ))

    task = PeriodicTask.objects.select_related("interval").get(name=f"aegis-report:{schedule.id}")
    assert updated.title == "Weekly risk review"
    assert updated.frequency == ReportSchedule.Frequency.WEEKLY
    assert updated.recipients == ["soc@example.com"]
    assert updated.enabled is False
    assert task.enabled is False
    assert task.interval.every == 10080
    assert task.interval.period == "minutes"


@pytest.mark.django_db
def test_report_schedule_delete_removes_beat_registration(report_projects):
    owner, _, project, _ = report_projects
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="evidence", frequency="monthly",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]

    async_to_sync(_delete_report_schedule)(str(schedule.id), str(owner.id))

    assert not ReportSchedule.objects.filter(pk=schedule.id).exists()
    assert not PeriodicTask.objects.filter(name=f"aegis-report:{schedule.id}").exists()


@pytest.mark.django_db
def test_report_schedule_lifecycle_is_owner_scoped(report_projects):
    owner, outsider, project, _ = report_projects
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]

    with pytest.raises(HTTPException) as get_error:
        async_to_sync(_get_report_schedule)(str(schedule.id), str(outsider.id))
    with pytest.raises(HTTPException) as update_error:
        async_to_sync(_update_report_schedule)(str(schedule.id), str(outsider.id), ReportScheduleUpdate(enabled=False))
    with pytest.raises(HTTPException) as execution_error:
        async_to_sync(_list_report_schedule_executions)(str(schedule.id), str(outsider.id))

    assert get_error.value.status_code == 404
    assert update_error.value.status_code == 404
    assert execution_error.value.status_code == 404
    assert ReportSchedule.objects.get(pk=schedule.id).enabled is True


@pytest.mark.django_db
def test_expired_report_artifact_is_removed_but_schedule_provenance_is_preserved(report_projects, settings, tmp_path):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-retention-proof")
    report = DataExport.objects.get(pk=result["report_id"])
    artifact_path = report.file.path
    DataExport.objects.filter(pk=report.id).update(expires_at=django_timezone.now()-timedelta(seconds=1))

    expired = expire_report_exports.run()

    report.refresh_from_db()
    execution = ReportScheduleExecution.objects.get(delivery_id="report-retention-proof")
    assert expired["expired"] == 1
    assert expired["failed"] == []
    assert report.status == DataExport.Status.EXPIRED
    assert not report.file
    assert report.file_size > 0
    assert execution.report_id == report.id
    assert not Path(artifact_path).exists()
    assert expire_report_exports.run()["expired"] == 0


@pytest.mark.django_db
def test_report_expiration_storage_failure_is_durable_and_retryable(report_projects, settings, tmp_path, monkeypatch):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    report = DataExport.objects.create(
        user=owner, name="Retention failure", format="json", status=DataExport.Status.COMPLETED,
        resource_type="project_report", filters={"project_id":str(project.id)}, fields=[],
        expires_at=django_timezone.now()-timedelta(seconds=1), completed_at=django_timezone.now(),
    )
    report.file.save(f"{report.id}.json", ContentFile(b"{}"))
    storage = report.file.storage
    real_delete = storage.delete
    monkeypatch.setattr(storage, "delete", lambda _name: (_ for _ in ()).throw(OSError("storage unavailable")))

    failed = expire_report_exports.run()

    report.refresh_from_db()
    assert failed["expired"] == 0
    assert failed["failed"][0]["report_id"] == str(report.id)
    assert report.status == DataExport.Status.COMPLETED
    assert report.file
    assert "storage unavailable" in report.error_message

    monkeypatch.setattr(storage, "delete", real_delete)
    retried = expire_report_exports.run()
    report.refresh_from_db()
    assert retried["expired"] == 1
    assert report.status == DataExport.Status.EXPIRED
    assert report.error_message == ""


@pytest.mark.django_db
def test_report_retention_setting_controls_new_artifact_expiry(report_projects, settings, tmp_path):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    settings.REPORT_RETENTION_DAYS = 31
    schedule = async_to_sync(_create_report_schedules)(ReportScheduleCreate(
        project_id=str(project.id), template_id="full", frequency="daily",
        recipients=[owner.email], formats=["json"],
    ), str(owner.id))[0]
    before = django_timezone.now()

    result = execute_report_schedule.run(str(schedule.id), delivery_id="report-retention-setting")

    report = DataExport.objects.get(pk=result["report_id"])
    assert before+timedelta(days=31) <= report.expires_at <= django_timezone.now()+timedelta(days=31)


@pytest.mark.django_db
def test_expired_report_and_expired_share_token_are_denied(report_projects, settings, tmp_path):
    owner, _, project, _ = report_projects
    settings.MEDIA_ROOT = tmp_path
    report = DataExport.objects.create(
        user=owner, name="Expired access", format="json", status=DataExport.Status.COMPLETED,
        resource_type="project_report", filters={"project_id":str(project.id)}, fields=[],
        expires_at=django_timezone.now()-timedelta(seconds=1), completed_at=django_timezone.now(),
    )
    report.file.save(f"{report.id}.json", ContentFile(b"{}"))
    expired_token = dumps({
        "report_id":str(report.id), "permission":"download", "recipient":owner.email,
        "expires_at":(django_timezone.now()-timedelta(seconds=1)).timestamp(),
    }, salt="aegisscan-report-share")

    with pytest.raises(HTTPException) as direct_error:
        async_to_sync(download_report)(str(report.id), {"user_id":str(owner.id)})
    with pytest.raises(HTTPException) as shared_error:
        async_to_sync(download_shared_report)(expired_token)
    with pytest.raises(HTTPException) as share_error:
        async_to_sync(share_report)(str(report.id), owner.email, "download", 7, {"user_id":str(owner.id)})

    assert direct_error.value.status_code == 410
    assert shared_error.value.status_code == 401
    assert share_error.value.status_code == 409


@pytest.mark.django_db(transaction=True)
def test_report_schedule_http_lifecycle_uses_persisted_state(transactional_db, settings, tmp_path):
    settings.MEDIA_ROOT = tmp_path
    user = User.objects.create_user(
        email="report-api@example.invalid", password="Strong-Test-Password-123!",
        role=UserRole.SECURITY_MANAGER,
    )
    project = Project.objects.create(name="Report API", slug="report-api", owner=user)
    test_app = FastAPI()
    test_app.include_router(reports_router.router, prefix="/api/v1/reports")
    test_app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        "user_id": str(user.id), "is_staff": False,
    }
    client = TestClient(test_app)
    try:
        with client:
            created = client.post("/api/v1/reports/schedules", json={
                "project_id": str(project.id), "template_id": "full", "frequency": "daily",
                "recipients": [user.email], "formats": ["json"],
            })
            assert created.status_code == 201
            schedule_id = created.json()[0]["id"]

            updated = client.patch(f"/api/v1/reports/schedules/{schedule_id}", json={
                "frequency": "weekly", "enabled": False,
            })
            assert updated.status_code == 200
            assert updated.json()["frequency"] == "weekly"
            assert updated.json()["enabled"] is False

            executions = client.get(f"/api/v1/reports/schedules/{schedule_id}/executions")
            assert executions.status_code == 200
            assert executions.json() == []

            deleted = client.delete(f"/api/v1/reports/schedules/{schedule_id}")
            assert deleted.status_code == 204
            assert client.get(f"/api/v1/reports/schedules/{schedule_id}").status_code == 404
    finally:
        if client.portal is not None:
            client.portal.call(sync_to_async(connections.close_all, thread_sensitive=True))
        test_app.dependency_overrides.clear()
