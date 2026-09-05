from asgiref.sync import async_to_sync
import pytest

from django_celery_beat.models import PeriodicTask

from django_project.projects.models import Project
from django_project.users.models import User
from django_project.audit.models import DataExport
from enterprise.models import ReportSchedule, ReportScheduleExecution
from enterprise.tasks import dispatch_due_schedules, execute_report_schedule
from fastapi import HTTPException
from fastapi_app.routers import reports as reports_router
from fastapi_app.routers.reports import (
    ReportScheduleCreate,
    _create_report_schedules,
    _list_report_schedules,
    router,
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

    replay = execute_report_schedule.run(str(schedule.id), delivery_id="report-delivery-1")

    assert replay == {
        "status": "completed", "schedule_id": str(schedule.id),
        "report_id": str(report.id), "replayed": True,
    }
    assert DataExport.objects.filter(resource_type="project_report").count() == 1
    execution.refresh_from_db()
    assert execution.attempts == 1


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
