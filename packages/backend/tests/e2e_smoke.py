import json
import os
import sys
import time
import urllib.error
import urllib.request

import pytest


pytestmark = pytest.mark.skipif(
    os.getenv("AEGIS_RUNTIME_E2E") != "1",
    reason="Service E2E smoke tests require the running CI/runtime stack",
)

DJANGO_URL = os.getenv("E2E_DJANGO_URL", "http://127.0.0.1:8000")
FASTAPI_URL = os.getenv("E2E_FASTAPI_URL", "http://127.0.0.1:8001")
E2E_EMAIL = os.getenv("E2E_EMAIL", "e2e@aegisscan.local")
E2E_PASSWORD = os.getenv("E2E_PASSWORD", "E2E-Password-12345!")


def _request(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, str]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def _get(url: str) -> tuple[int, str]:
    return _request(url)


def _wait_for(url: str, attempts: int = 30) -> None:
    last_error = None
    for _ in range(attempts):
        try:
            status, _ = _get(url)
            if status == 200:
                return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
        time.sleep(2)
    raise AssertionError(f"Service did not become healthy: {url}; last_error={last_error}")


def _seed_e2e_tenant() -> None:
    """Create an isolated CI tenant used only by this runtime smoke suite."""
    backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if backend_root not in sys.path:
        sys.path.insert(0, backend_root)

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
    import django

    django.setup()

    from django.utils import timezone
    from projects.models import Project
    from users.models import User, UserRole

    user, created = User.objects.get_or_create(
        email=E2E_EMAIL,
        defaults={
            "first_name": "E2E",
            "last_name": "Runner",
            "role": UserRole.ADMIN,
            "is_active": True,
        },
    )
    user.set_password(E2E_PASSWORD)
    user.role = UserRole.ADMIN
    user.is_active = True
    if created or not user.is_verified:
        user.is_verified = True
    user.save(update_fields=["password", "role", "is_active", "is_verified"])

    Project.objects.update_or_create(
        slug="e2e-runtime-project",
        defaults={
            "name": "E2E Runtime Project",
            "description": "Ephemeral tenant used by runtime E2E verification",
            "owner": user,
            "updated_at": timezone.now(),
        },
    )


def test_django_and_fastapi_health_contract():
    _wait_for(f"{DJANGO_URL}/health/")
    _wait_for(f"{FASTAPI_URL}/health")


def test_jwt_login_refresh_and_dashboard_contract():
    _seed_e2e_tenant()

    status, body = _request(
        f"{DJANGO_URL}/api/v1/auth/login/",
        method="POST",
        payload={"email": E2E_EMAIL, "password": E2E_PASSWORD},
    )
    assert status == 200, f"JWT login failed: {status} {body}"

    login = json.loads(body)
    access_token = login.get("access")
    refresh_token = login.get("refresh")
    assert access_token, "JWT access token missing"
    assert refresh_token, "JWT refresh token missing"
    assert login.get("user"), "Authenticated user payload missing"

    status, body = _request(
        f"{DJANGO_URL}/api/v1/dashboard/summary",
        token=access_token,
    )
    assert status == 200, f"Authenticated dashboard request failed: {status} {body}"

    dashboard = json.loads(body)
    required_keys = {
        "security_score",
        "total_projects",
        "total_assets",
        "total_validations",
        "critical",
        "high",
    }
    assert required_keys.issubset(dashboard), (
        "Dashboard contract missing keys: "
        f"{sorted(required_keys - set(dashboard))}"
    )
    assert dashboard["total_projects"] >= 1

    status, body = _request(
        f"{DJANGO_URL}/api/v1/auth/refresh/",
        method="POST",
        payload={"refresh": refresh_token},
    )
    assert status == 200, f"JWT refresh failed: {status} {body}"

    refreshed = json.loads(body)
    assert refreshed.get("access"), "Refreshed JWT access token missing"

    unauth_status, _ = _get(f"{DJANGO_URL}/api/v1/dashboard/summary")
    assert unauth_status in {401, 403}, (
        f"Dashboard unexpectedly allowed unauthenticated access: {unauth_status}"
    )


def test_durable_resource_crud_is_not_exposed_by_fastapi():
    for resource in (
        "assets",
        "scans",
        "vulnerabilities",
        "reports",
        "compliance",
        "audit",
    ):
        status, _ = _get(f"{FASTAPI_URL}/api/v1/{resource}/")
        assert status == 404, (
            f"FastAPI unexpectedly exposes durable CRUD: {resource}"
        )
