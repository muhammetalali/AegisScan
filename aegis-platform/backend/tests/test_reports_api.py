from django.urls import reverse
from projects.models import Project
from reports.models import Report
from rest_framework.test import APITestCase
from users.models import User


class ReportApiTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.com",
            password="StrongPassword123!",
            first_name="Project",
            last_name="Owner",
        )
        self.member = User.objects.create_user(
            email="member@example.com",
            password="StrongPassword123!",
            first_name="Project",
            last_name="Member",
        )
        self.outsider = User.objects.create_user(
            email="outsider@example.com",
            password="StrongPassword123!",
            first_name="Project",
            last_name="Outsider",
        )
        self.project = Project.objects.create(
            name="Durable reports",
            slug="durable-reports",
            owner=self.owner,
        )
        self.project.members.add(self.member)
        self.list_url = reverse("report-list")

    def test_owner_can_create_and_member_can_read_report(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post(
            self.list_url,
            {
                "project_id": str(self.project.id),
                "title": "Weekly assurance",
                "report_type": Report.Type.FULL,
                "format": Report.Format.MARKDOWN,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
        report = Report.objects.get(pk=response.data["id"])
        self.assertEqual(report.generated_by_id, self.owner.id)
        self.assertEqual(str(response.data["project_id"]), str(self.project.id))

        self.client.force_authenticate(self.member)
        detail = self.client.get(reverse("report-detail", args=[report.id]))
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["title"], "Weekly assurance")

    def test_outsider_cannot_read_or_delete_project_report(self):
        report = Report.objects.create(
            project=self.project,
            title="Private report",
            generated_by=self.owner,
        )
        self.client.force_authenticate(self.outsider)

        self.assertEqual(
            self.client.get(reverse("report-detail", args=[report.id])).status_code,
            404,
        )
        self.assertEqual(
            self.client.delete(reverse("report-detail", args=[report.id])).status_code,
            404,
        )

    def test_project_member_can_read_but_cannot_mutate_reports(self):
        report = Report.objects.create(
            project=self.project,
            title="Member read-only report",
            generated_by=self.owner,
        )
        self.client.force_authenticate(self.member)

        create = self.client.post(
            self.list_url,
            {"project_id": str(self.project.id), "title": "Not allowed"},
            format="json",
        )
        self.assertEqual(create.status_code, 403)
        self.assertEqual(
            self.client.delete(reverse("report-detail", args=[report.id])).status_code,
            403,
        )

    def test_report_lifecycle_and_download_are_persistent(self):
        self.client.force_authenticate(self.owner)
        create = self.client.post(
            self.list_url,
            {"project_id": str(self.project.id), "title": "Lifecycle report"},
            format="json",
        )
        report_id = create.data["id"]
        self.assertEqual(create.data["status"], Report.Status.GENERATING)

        not_ready = self.client.get(
            reverse("report-download", args=[report_id])
        )
        self.assertEqual(not_ready.status_code, 409)

        complete = self.client.post(
            reverse("report-complete", args=[report_id]),
            {"content": "# Completed report"},
            format="json",
        )
        self.assertEqual(complete.status_code, 200)
        self.assertEqual(complete.data["status"], Report.Status.COMPLETED)

        download = self.client.get(reverse("report-download", args=[report_id]))
        self.assertEqual(download.status_code, 200)
        self.assertIn("Completed report", download.content.decode())
        self.assertEqual(Report.objects.get(pk=report_id).download_count, 1)
