from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)

def test_multi_tenant_investigation_and_attack_path_access_is_isolated():
    owner=User.objects.create_user(email='tenant-owner@example.invalid',password='Strong-Test-Password-123!')
    outsider=User.objects.create_user(email='tenant-outsider@example.invalid',password='Strong-Test-Password-123!')
    project=Project.objects.create(name='Tenant Private',slug='tenant-private',owner=owner)
    app.dependency_overrides[get_current_user]=lambda:{'user_id':str(outsider.id)}
    try:
        client=TestClient(app)
        for path in (f'/api/v1/investigation/projects/{project.id}',f'/api/v1/attack-path/projects/{project.id}',f'/api/v1/digital-twin/projects/{project.id}/twins'):
            response=client.get(path)
            assert response.status_code in {403,404},(path,response.status_code,response.text)
    finally:
        app.dependency_overrides.clear()
