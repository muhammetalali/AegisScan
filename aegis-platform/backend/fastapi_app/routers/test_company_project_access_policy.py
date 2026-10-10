"""Primary owner visibility without removing employee project isolation."""
from __future__ import annotations

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from django_project.assets.models import Asset
from django_project.projects.models import Project, ProjectMembership
from django_project.users.models import User
from fastapi_app.core.dependencies import project_access_q


@pytest.mark.django_db(transaction=True)
def test_owner_can_read_company_projects_and_assets_without_membership(settings):
    primary = User.objects.create_superuser(
        email=settings.AEGIS_PRIMARY_OWNER_EMAIL,
        password="Test-Primary-Owner-Pass-2026!",
    )
    alice = User.objects.create_user(
        email="scope-alice@example.invalid", password="Test-Alice-Pass-2026!"
    )
    bob = User.objects.create_user(
        email="scope-bob@example.invalid", password="Test-Bob-Pass-2026!"
    )
    first = Project.objects.create(name="One", slug="scope-one", owner=alice)
    second = Project.objects.create(name="Two", slug="scope-two", owner=bob)
    ProjectMembership.objects.create(project=first, user=bob)
    asset = Asset.objects.create(
        project=second,
        owner=bob,
        name="Asset in second project",
        slug="scope-asset-second",
        type=Asset.Type.IP_ADDRESS,
    )
    with CaptureQueriesContext(connection) as captured:
        owner_projects = list(
            Project.objects.filter(project_access_q(str(primary.pk)))
            .order_by("slug").values_list("slug", flat=True)
        )
    assert owner_projects == ["scope-one", "scope-two"]
    from fastapi_app.core.dependencies import accessible_projects_for_user
    assert list(accessible_projects_for_user(str(primary.pk)).order_by("slug").values_list("slug", flat=True)) == owner_projects
    assert len([q for q in captured if q["sql"].lstrip().upper().startswith("SELECT")]) == 1

    assert list(Project.objects.filter(project_access_q(str(alice.pk)))) == [first]
    assert list(accessible_projects_for_user(str(alice.pk))) == [first]
    assert set(Project.objects.filter(project_access_q(str(bob.pk)))) == {first, second}
    assert list(Asset.objects.filter(project_access_q(str(primary.pk), relation="project"))) == [asset]
    assert not Asset.objects.filter(project_access_q(str(alice.pk), relation="project")).exists()


@pytest.mark.django_db(transaction=True)
def test_inactive_or_other_superuser_cannot_impersonate_primary_owner(settings):
    owner = User.objects.create_superuser(
        email=settings.AEGIS_PRIMARY_OWNER_EMAIL,
        password="Test-Primary-Owner-Pass-2026!",
    )
    another = User.objects.create_superuser(
        email="other-admin-scope@example.invalid",
        password="Test-Other-Admin-Pass-2026!",
    )
    project_owner = User.objects.create_user(
        email="project-owner-scope@example.invalid",
        password="Test-Project-Owner-Pass-2026!",
    )
    Project.objects.create(name="Owned", slug="scope-protected", owner=project_owner)
    assert not Project.objects.filter(project_access_q(str(another.pk))).exists()
    assert Project.objects.filter(project_access_q(str(owner.pk))).exists()
    owner.is_active = False
    owner.save(update_fields=["is_active"])
    assert not Project.objects.filter(project_access_q(str(owner.pk))).exists()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("route", [
    "/api/v1/investigation/projects/{project_id}",
    "/api/v1/posture/projects/{project_id}/posture",
    "/api/v1/posture/projects/{project_id}/history",
    "/api/v1/compliance/projects/{project_id}/dashboard",
    "/api/v1/compliance/projects/{project_id}/assessments",
    "/api/v1/attack-path/projects/{project_id}",
    "/api/v1/risk-correlation/projects/{project_id}",
    "/api/v1/fair-risk/projects/{project_id}/analyses",
    "/api/v1/wstg/projects/{project_id}/coverage",
    "/api/v1/provider-approvals/projects/{project_id}/decisions",
])
def test_workspace_routes_allow_primary_owner_but_reject_unrelated_employee(settings, route):
    from fastapi.testclient import TestClient
    from fastapi_app.core.dependencies import get_current_user
    from fastapi_app.main import app

    primary = User.objects.create_superuser(
        email=settings.AEGIS_PRIMARY_OWNER_EMAIL, password="Owner-Route-Test-2026!",
    )
    employee = User.objects.create_user(email="employee-route@example.invalid", password="Employee-Route-Test-2026!")
    outsider = User.objects.create_user(email="outsider-route@example.invalid", password="Outsider-Route-Test-2026!")
    project = Project.objects.create(name="Company route", slug="company-route", owner=employee)
    url = route.format(project_id=project.id)
    previous = app.dependency_overrides.copy()
    try:
        with TestClient(app) as client:
            app.dependency_overrides[get_current_user] = lambda: {"user_id": str(primary.pk)}
            response = client.get(url)
            assert response.status_code == 200, response.text
            # An employee cannot acquire company visibility by forging owner claims.
            app.dependency_overrides[get_current_user] = lambda: {
                "user_id": str(outsider.pk), "is_company_owner": True, "is_staff": True,
            }
            denied = client.get(url)
            assert denied.status_code in (403, 404), denied.text
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.mark.django_db(transaction=True)
def test_django_project_api_includes_company_projects_for_owner_only(settings):
    from rest_framework.test import APIRequestFactory, force_authenticate
    from django_project.projects.views import ProjectViewSet

    primary = User.objects.create_superuser(email=settings.AEGIS_PRIMARY_OWNER_EMAIL, password="Owner-Projects-Test-2026!")
    employee = User.objects.create_user(email="employee-projects@example.invalid", password="Employee-Projects-Test-2026!")
    outsider = User.objects.create_user(email="outsider-projects@example.invalid", password="Outsider-Projects-Test-2026!")
    project = Project.objects.create(name="Visible company project", slug="visible-company-project", owner=employee)
    view = ProjectViewSet.as_view({"get": "retrieve"})
    for actor, expected in ((primary, 200), (employee, 200), (outsider, 404)):
        request = APIRequestFactory().get(f"/projects/{project.pk}/")
        force_authenticate(request, user=actor)
        response = view(request, pk=str(project.pk))
        assert response.status_code == expected, response.data
