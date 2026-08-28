from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from assets.models import Asset
from projects.models import Project, ProjectMembership
from scans.models import Scan
from vulnerabilities.models import Vulnerability


class DashboardContractTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            email='dashboard@example.com',
            password='StrongPassword123!',
            first_name='Dashboard',
            last_name='User',
            is_active=True,
        )
        self.other = User.objects.create_user(
            email='other@example.com',
            password='StrongPassword123!',
            first_name='Other',
            last_name='User',
            is_active=True,
        )
        self.project = Project.objects.create(
            name='Visible Project', slug='visible-project', owner=self.user
        )
        self.foreign_project = Project.objects.create(
            name='Foreign Project', slug='foreign-project', owner=self.other
        )
        ProjectMembership.objects.create(project=self.project, user=self.user, role='owner')
        self.asset = Asset.objects.create(
            project=self.project,
            name='Web App',
            slug='web-app',
            type='website',
        )
        Scan.objects.create(
            project=self.project,
            name='Baseline',
            scan_type='url',
            status='completed',
            security_score=82,
            findings_count=2,
            asset=self.asset,
            initiated_by=self.user,
        )
        Scan.objects.create(
            project=self.foreign_project,
            name='Foreign Scan',
            scan_type='url',
            status='completed',
            security_score=10,
            asset=None,
            initiated_by=self.other,
        )
        Vulnerability.objects.create(
            project=self.project,
            scan=Scan.objects.filter(project=self.project).first(),
            asset=self.asset,
            title='Critical issue',
            description='Critical issue',
            severity='critical',
            status='open',
        )

    def test_requires_authentication(self):
        for path in (
            '/api/v1/dashboard/summary',
            '/api/v1/dashboard/risk-distribution',
            '/api/v1/dashboard/trends?days=30',
            '/api/v1/dashboard/recent-validations?limit=5',
        ):
            response = self.client.get(path)
            self.assertIn(response.status_code, (401, 403))

    def test_dashboard_is_scoped_to_visible_projects(self):
        self.client.force_authenticate(self.user)
        summary = self.client.get('/api/v1/dashboard/summary')
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.data['total_projects'], 1)
        self.assertEqual(summary.data['total_assets'], 1)
        self.assertEqual(summary.data['total_validations'], 1)
        self.assertEqual(summary.data['security_score'], 82.0)
        self.assertEqual(summary.data['critical'], 1)

        risk = self.client.get('/api/v1/dashboard/risk-distribution')
        self.assertEqual(risk.status_code, 200)
        self.assertEqual(risk.data['critical'], 1)
        self.assertEqual(risk.data['high'], 0)

        recent = self.client.get('/api/v1/dashboard/recent-validations?limit=5')
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(len(recent.data), 1)
        self.assertEqual(recent.data[0]['project_name'], 'Visible Project')
