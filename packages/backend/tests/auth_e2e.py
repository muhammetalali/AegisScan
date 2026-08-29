from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager

from websockets.exceptions import ConnectionClosed, InvalidStatus
from websockets.sync.client import connect


DJANGO_URL = os.getenv("E2E_DJANGO_URL", "http://127.0.0.1:8000")
FASTAPI_URL = os.getenv("E2E_FASTAPI_URL", "http://127.0.0.1:8001")
E2E_EMAIL = os.getenv("AUTH_E2E_EMAIL", "auth-e2e@aegisscan.local")
E2E_PASSWORD = os.getenv("AUTH_E2E_PASSWORD", "Auth-E2E-2026!x9")


def _request(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, str]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def _django_setup():
    backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if backend_root not in sys.path:
        sys.path.insert(0, backend_root)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
    import django

    django.setup()
    return django


def _seed_user(role: str = "admin") -> None:
    _django_setup()
    from users.models import User, UserRole

    user, _ = User.objects.get_or_create(
        email=E2E_EMAIL,
        defaults={
            "first_name": "Auth",
            "last_name": "E2E",
            "role": UserRole(role),
            "is_active": True,
            "is_verified": True,
        },
    )
    user.set_password(E2E_PASSWORD)
    user.role = UserRole(role)
    user.is_active = True
    user.is_verified = True
    user.save(update_fields=["password", "role", "is_active", "is_verified"])


def _cleanup_user() -> None:
    try:
        _django_setup()
        from users.models import User

        User.objects.filter(email=E2E_EMAIL).delete()
    except Exception:
        pass


@contextmanager
def _user(role: str = "admin"):
    _seed_user(role)
    try:
        yield
    finally:
        _cleanup_user()


def _login() -> tuple[str, str]:
    status, body = _request(
        f"{DJANGO_URL}/api/v1/auth/login/",
        method="POST",
        payload={"email": E2E_EMAIL, "password": E2E_PASSWORD},
    )
    assert status == 200, f"Login failed: {status} {body}"
    data = json.loads(body)
    assert data.get("user", {}).get("email") == E2E_EMAIL
    return data["access"], data["refresh"]


def test_auth_e2e_login_cross_service_and_refresh() -> None:
    with _user("admin"):
        access_token, refresh_token = _login()

        status, body = _request(
            f"{DJANGO_URL}/api/v1/dashboard/summary", token=access_token
        )
        assert status == 200, f"Django protected API failed: {status} {body}"

        status, body = _request(
            f"{FASTAPI_URL}/api/v1/assurance/correlations/summary",
            token=access_token,
        )
        assert status == 200, f"FastAPI JWT validation failed: {status} {body}"

        status, body = _request(
            f"{DJANGO_URL}/api/v1/auth/refresh/",
            method="POST",
            payload={"refresh": refresh_token},
        )
        assert status == 200, f"Refresh failed: {status} {body}"
        refreshed = json.loads(body)
        assert refreshed.get("access")

        status, body = _request(
            f"{DJANGO_URL}/api/v1/auth/refresh/",
            method="POST",
            payload={"refresh": refresh_token},
        )
        assert status == 401, f"Rotated refresh token was reusable: {status} {body}"

        status, body = _request(
            f"{FASTAPI_URL}/api/v1/assurance/correlations/summary",
            token="not-a-valid-jwt",
        )
        assert status == 401, f"Invalid JWT was accepted: {status} {body}"


def test_auth_e2e_session_version_revokes_access_token() -> None:
    with _user("security_analyst"):
        access_token, _ = _login()
        _django_setup()
        from users.models import User

        user = User.objects.get(email=E2E_EMAIL)
        old_version = int(user.session_version)
        user.session_version = old_version + 1
        user.save(update_fields=["session_version"])

        status, body = _request(
            f"{FASTAPI_URL}/api/v1/assurance/correlations/summary",
            token=access_token,
        )
        assert status == 401, f"Stale JWT was accepted: {status} {body}"


def test_auth_e2e_rbac_denies_viewer_privileged_operation() -> None:
    with _user("viewer"):
        access_token, _ = _login()
        status, body = _request(
            f"{DJANGO_URL}/api/v1/users/users/999999/",
            method="DELETE",
            token=access_token,
        )
        assert status == 403, f"Viewer privilege escalation was allowed: {status} {body}"


def test_auth_e2e_websocket_requires_bearer_and_supports_live_revocation() -> None:
    with _user("security_analyst"):
        access_token, _ = _login()
        _django_setup()
        from users.models import User

        user = User.objects.get(email=E2E_EMAIL)
        original_version = int(user.session_version)

        try:
            connect("ws://127.0.0.1:8001/ws/workflow", open_timeout=10)
        except InvalidStatus as exc:
            assert "500" not in str(exc), "Missing WebSocket credentials caused HTTP 500"
        else:
            raise AssertionError("Unauthenticated WebSocket unexpectedly connected")

        try:
            connect(
                "ws://127.0.0.1:8001/ws/workflow",
                subprotocols=["bearer", "invalid-token"],
                open_timeout=10,
            )
        except InvalidStatus:
            pass
        else:
            raise AssertionError("Invalid WebSocket JWT unexpectedly connected")

        with connect(
            "ws://127.0.0.1:8001/ws/workflow",
            subprotocols=["bearer", access_token],
            open_timeout=10,
            close_timeout=5,
        ) as websocket:
            connected = json.loads(websocket.recv(timeout=5))
            assert connected == {
                "type": "workflow.connected",
                "user_id": str(user.id),
            }

            user.session_version = original_version + 1
            user.save(update_fields=["session_version"])

            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    message = json.loads(websocket.recv(timeout=2))
                except TimeoutError:
                    continue
                assert message == {
                    "type": "auth.revoked",
                    "reason": "session_revoked",
                }
                break
            else:
                raise AssertionError("Timed out waiting for live auth.revoked event")

            try:
                websocket.recv(timeout=5)
            except ConnectionClosed as exc:
                assert exc.code == 4001, f"Unexpected revocation close code: {exc.code}"
                assert exc.reason == "Authentication revoked"
            else:
                raise AssertionError("WebSocket remained open after live revocation")
