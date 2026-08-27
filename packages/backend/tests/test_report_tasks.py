import hashlib
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from fastapi_app.tasks.report_tasks import generate_report
from projects.models import Project
from reports.models import Report, ReportSchedule, ReportTemplate
from users.models import User


class ReportTaskTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="report-worker@example.com",
            password="StrongPassword123!",
            first_name="Report",
            last_name="Worker",
        )
        self.project = Project.objects.create(
            name="Worker reports",
            slug="worker-reports",
            owner=self.user,
        )

    def test_task_generates_json_and_persists_hash(self):
        report = Report.objects.create(
            project=self.project,
            title="Worker JSON report",
            format=Report.Format.JSON,
            generated_by=self.user,
            data_snapshot={"finding_count": 3},
        )

        result = generate_report.run(str(report.id), {"source": "test"})
        report.refresh_from_db()

        self.assertEqual(result["status"], Report.Status.COMPLETED)
        self.assertEqual(report.status, Report.Status.COMPLETED)
        self.assertIn('"finding_count": 3', report.content)
        self.assertEqual(report.file_size, len(report.content.encode("utf-8")))
        self.assertEqual(report.file_hash, hashlib.sha256(report.content.encode()).hexdigest())

    def test_task_generates_a_valid_pdf_artifact(self):
        report = Report.objects.create(
            project=self.project,
            title="Worker PDF report",
            format=Report.Format.PDF,
            generated_by=self.user,
        )
        with tempfile.TemporaryDirectory() as media_dir:
            with override_settings(MEDIA_ROOT=media_dir):
                generate_report.run(str(report.id), {})
                report.refresh_from_db()
                artifact = Path(media_dir) / report.file.name
                self.assertEqual(report.status, Report.Status.COMPLETED)
                self.assertTrue(artifact.exists())
                self.assertTrue(artifact.read_bytes().startswith(b"%PDF-1.4"))

    def test_unsupported_format_is_persisted_as_failed(self):
        report = Report.objects.create(
            project=self.project,
            title="Worker DOCX report",
            format=Report.Format.DOCX,
            generated_by=self.user,
        )

        with self.assertRaises(ValueError):
            generate_report.run(str(report.id), {})
        report.refresh_from_db()
        self.assertEqual(report.status, Report.Status.FAILED)
        self.assertIn("Unsupported report format", report.error_message)

    @patch("fastapi_app.tasks.report_tasks.generate_report.delay")
    def test_due_schedule_creates_and_queues_report(self, queue_report):
        template = ReportTemplate.objects.create(
            name="Daily markdown",
            report_type=Report.Type.TECHNICAL,
            format=Report.Format.MARKDOWN,
            template_content="{{ report }}",
            created_by=self.user,
        )
        schedule = ReportSchedule.objects.create(
            project=self.project,
            name="Daily assurance",
            template=template,
            frequency=ReportSchedule.Frequency.DAILY,
            next_generation=timezone.now() - timedelta(minutes=1),
            created_by=self.user,
        )

        from fastapi_app.tasks.report_tasks import generate_scheduled_reports

        result = generate_scheduled_reports.run()
        schedule.refresh_from_db()
        report = Report.objects.get(template_used=str(template.id))

        self.assertEqual(result, {"queued": 1})
        self.assertEqual(report.status, Report.Status.GENERATING)
        self.assertGreater(schedule.next_generation, timezone.now())
        queue_report.assert_called_once_with(
            str(report.id),
            {"scheduled": True, "schedule_id": str(schedule.id)},
        )
