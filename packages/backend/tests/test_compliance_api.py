from django.urls import reverse
from rest_framework.test import APITestCase

from compliance.models import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
)
from projects.models import Project
from users.models import User


class ComplianceApiTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="compliance-owner@example.com",
            password="StrongPassword123!",
            first_name="Compliance",
            last_name="Owner",
        )
        self.member = User.objects.create_user(
            email="compliance-member@example.com",
            password="StrongPassword123!",
            first_name="Compliance",
            last_name="Member",
        )
        self.outsider = User.objects.create_user(
            email="compliance-outsider@example.com",
            password="StrongPassword123!",
            first_name="Compliance",
            last_name="Outsider",
        )
        self.project = Project.objects.create(
            name="Compliance project",
            slug="compliance-project",
            owner=self.owner,
        )
        self.project.members.add(self.member)
        self.framework = ComplianceFramework.objects.create(
            name="Test Framework",
            framework_type=ComplianceFramework.FrameworkType.CUSTOM,
            version="1.0",
        )
        self.control = ComplianceControl.objects.create(
            framework=self.framework,
            control_id="AC-1",
            title="Access control policy",
            description="A sufficiently detailed test control description.",
        )

    def test_frameworks_and_controls_are_real_data(self):
        self.client.force_authenticate(self.member)
        frameworks = self.client.get(reverse("compliance-framework-list"))
        self.assertEqual(frameworks.status_code, 200)
        self.assertEqual(frameworks.data["results"][0]["name"], "Test Framework")
        controls = self.client.get(
            reverse("compliance-framework-controls", args=[self.framework.id])
        )
        self.assertEqual(controls.status_code, 200)
        self.assertEqual(controls.data[0]["control_id"], "AC-1")

    def test_owner_can_assess_and_generate_report(self):
        self.client.force_authenticate(self.owner)
        assessment = self.client.post(
            reverse("compliance-assessment-list"),
            {
                "project_id": str(self.project.id),
                "framework_id": str(self.framework.id),
                "control_id": str(self.control.id),
                "status": ComplianceAssessment.Status.COMPLIANT,
                "evidence": "Reviewed access control policy and approval record.",
            },
            format="json",
        )
        self.assertEqual(assessment.status_code, 201)
        report = self.client.post(
            reverse("compliance-report-generate"),
            {
                "project_id": str(self.project.id),
                "framework_id": str(self.framework.id),
            },
            format="json",
        )
        self.assertEqual(report.status_code, 201)
        self.assertEqual(report.data["compliance_percentage"], 100.0)
        self.assertEqual(report.data["report_data"]["controls"][0]["status"], "compliant")

    def test_outsider_cannot_read_project_assessments_or_dashboard(self):
        ComplianceAssessment.objects.create(
            project=self.project,
            framework=self.framework,
            control=self.control,
            status=ComplianceAssessment.Status.NON_COMPLIANT,
            assessed_by=self.owner,
        )
        self.client.force_authenticate(self.outsider)
        assessments = self.client.get(reverse("compliance-assessment-list"))
        self.assertEqual(assessments.status_code, 200)
        self.assertEqual(assessments.data["count"], 0)
        dashboard = self.client.get(
            reverse("compliance-report-dashboard"),
            {"project_id": str(self.project.id)},
        )
        self.assertEqual(dashboard.status_code, 404)
