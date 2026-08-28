import json
import os
import time
import urllib.error
import urllib.request


DJANGO_URL = os.getenv("E2E_DJANGO_URL", "http://127.0.0.1:8000")
FASTAPI_URL = os.getenv("E2E_FASTAPI_URL", "http://127.0.0.1:8001")
E2E_EMAIL = os.getenv("E2E_EMAIL", "e2e@aegisscan.local")
E2E_PASSWORD = os.getenv("E2E_PASSWORD", "E2E-Password-12345!")


def _request(url: str, method: str = "GET", payload: dict | None = None, token: str | None = None) -> tuple[int, str]:
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


def test_django_and_fastapi_health_contract():
    _wait_for(f"{DJANGO_URL}/health/")
    _wait_for(f"{FASTAPI_URL}/health")


def test_jwt_login_refresh_and_dashboard_contract():
    status, body = _request(
        f"{DJANGO_URL}/api/v1/auth/login/",
        method="POST",
        payload={"email": E2E_EMAIL, "password": E2E_PASSWORD},
    )
    assert status == 200, f"JWT login failed: {status} {body}"

    login = json.loads(body)
    assert login.get("access"), "JWT access token missing"
    assert login.get("refresh"), "JWT refresh token missing"
    access_token = login["access"]
    refresh_token = login["refresh"]

    status, body = _request(
        f"{DJANGO_URL}/api/v1/dashboard/summary",
        token=access_token,
    )
    assert status == 200, f"Authenticated dashboard request failed: {status} {body}"

    dashboard = json.loads(body)
    required_keys = {"security_score", "total_projects", "total_assets", "total_validations", "critical", "high"}
    assert required_keys.issubset(dashboard), f"Dashboard contract missing keys: {sorted(required_keys - set(dashboard))}"

    status, body = _request(
        f"{DJANGO_URL}/api/v1/auth/refresh/",
        method="POST",
        payload={"refresh": refresh_token},
    )
    assert status == 200, f"JWT refresh failed: {status} {body}"

    refreshed = json.loads(body)
    assert refreshed.get("access"), "Refreshed JWT access token missing"


def test_durable_resource_crud_is_not_exposed_by_fastapi():
    for resource in ("assets", "scans", "vulnerabilities", "reports", "compliance", "audit"):
        status, _ = _get(f"{FASTAPI_URL}/api/v1/{resource}/")
        assert status == 404, f"FastAPI unexpectedly exposes durable CRUD: {resource}"
