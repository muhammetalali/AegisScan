from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase

from django_project.users.models import UserRole

User = get_user_model()


class ProjectCreateAPITest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="project-api-test@aegisscan.local",
            password="Project-API-Test-StrongPass!9",
            first_name="Project",
            last_name="API Test",
            role=UserRole.SECURITY_MANAGER,
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=self.user)

    def test_create_returns_created_project_id(self):
        response = self.client.post(
            "/api/v1/projects/",
            {
                "name": "API Contract Project",
                "description": "Project creation response contract",
                "environment": "development",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertIn("id", response.data)
        self.assertTrue(response.data["id"])
        self.assertEqual(response.data["name"], "API Contract Project")
