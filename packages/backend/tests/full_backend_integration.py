from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager


DJANGO_URL = os.getenv("E2E_DJANGO_URL", "http://127.0.0.1:8000")
FASTAPI_URL = os.getenv("E2E_FASTAPI_URL", "http://127.0.0.1:8001")
E2E_EMAIL = os.getenv("E2E_EMAIL", "backend-integration@aegisscan.local")
E2E_PASSWORD = os.getenv("E2E_PASSWORD", "Backend-Integration-2026!x9")


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


def _wait_for(url: str, attempts: int = 45) -> None:
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            status, _ = _request(url)
            if status == 200:
                return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
        time.sleep(2)
    raise AssertionError(f"Service did not become healthy: {url}; last_error={last_error}")


def _manage_shell(code: str) -> str:
    backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    result = subprocess.run(
        [sys.executable, "manage.py", "shell", "-c", code],
        cwd=backend_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _seed_user() -> None:
    _manage_shell(
        """
from users.models import User, UserRole
user, _ = User.objects.get_or_create(
    email='backend-integration@aegisscan.local',
    defaults={
        'first_name': 'Backend',
        'last_name': 'Integration',
        'role': UserRole.ADMIN,
        'is_active': True,
        'is_verified': True,
    },
)
user.set_password('Backend-Integration-2026!x9')
user.role = UserRole.ADMIN
user.is_active = True
user.is_verified = True
user.save(update_fields=['password', 'role', 'is_active', 'is_verified'])
"""
    )


def _cleanup_user() -> None:
    try:
        _manage_shell(
            "from users.models import User; User.objects.filter(email='backend-integration@aegisscan.local').delete()"
        )
    except subprocess.CalledProcessError:
        pass


@contextmanager
def _integration_user():
    _seed_user()
    try:
        yield
    finally:
        _cleanup_user()


def _bump_session_version() -> None:
    _manage_shell(
        "from users.models import User; user=User.objects.get(email='backend-integration@aegisscan.local'); user.session_version += 1; user.save(update_fields=['session_version'])"
    )


def test_backend_runtime_contract() -> None:
    """Exercise Django, PostgreSQL, FastAPI, JWT, Redis/Celery and WebSocket as one runtime path."""
    _wait_for(f"{DJANGO_URL}/health/")
    _wait_for(f"{FASTAPI_URL}/health")

    import psycopg2
    from redis import Redis

    database_url = os.getenv("DATABASE_URL", "postgresql://aegis:aegis@127.0.0.1:5432/aegisdb")
    with psycopg2.connect(database_url) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            assert cursor.fetchone() == (1,)

    redis_url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    redis_client = Redis.from_url(redis_url, decode_responses=True)
    assert redis_client.ping() is True
    probe_key = "aegisscan:e2e:backend-integration"
    redis_client.set(probe_key, "ok", ex=30)
    assert redis_client.get(probe_key) == "ok"
    redis_client.delete(probe_key)

    with _integration_user():
        status, body = _request(
            f"{DJANGO_URL}/api/v1/auth/login/",
            method="POST",
            payload={"email": E2E_EMAIL, "password": E2E_PASSWORD},
        )
        assert status == 200, f"Django login failed: {status} {body}"
        login = json.loads(body)
        access_token = login.get("access")
        refresh_token = login.get("refresh")
        assert access_token and refresh_token
        assert login.get("user", {}).get("email") == E2E_EMAIL

        status, body = _request(f"{DJANGO_URL}/api/v1/dashboard/summary", token=access_token)
        assert status == 200, f"Django authenticated API failed: {status} {body}"

        status, body = _request(
            f"{FASTAPI_URL}/api/v1/assurance/correlations/summary",
            token=access_token,
        )
        assert status == 200, f"FastAPI rejected Django JWT: {status} {body}"
        summary = json.loads(body)
        assert {"conflicts", "signals", "sources", "agreement", "confidence"}.issubset(summary)

        status, _ = _request(
            f"{FASTAPI_URL}/api/v1/assurance/correlations/summary",
            token="invalid.jwt.token",
        )
        assert status == 401

        status, body = _request(
            f"{DJANGO_URL}/api/v1/auth/refresh/",
            method="POST",
            payload={"refresh": refresh_token},
        )
        assert status == 200, f"JWT refresh failed: {status} {body}"
        assert json.loads(body).get("access")

        _bump_session_version()
        status, body = _request(
            f"{FASTAPI_URL}/api/v1/assurance/correlations/summary",
            token=access_token,
        )
        assert status == 401, f"Revoked JWT unexpectedly accepted: {status} {body}"

        status, body = _request(f"{FASTAPI_URL}/openapi.json")
        assert status == 200, f"OpenAPI unavailable: {status} {body}"
        openapi = json.loads(body)
        assert "/api/v1/security-sessions" in openapi.get("paths", {})

        from fastapi_app.celery_app import celery_app
        from fastapi_app.tasks.health_tasks import celery_health

        inspector = celery_app.control.inspect(timeout=3)
        ping = inspector.ping() or {}
        assert ping, "No live Celery workers responded"
        assert any(
            isinstance(response, dict) and response.get("ok") == "pong"
            for response in ping.values()
        ), f"Celery workers did not respond with pong: {ping!r}"

        result = celery_health.apply_async(queue="health", routing_key="health")
        payload = result.get(timeout=20, propagate=True)
        assert result.successful()
        assert payload["status"] == "ok"
        assert payload["worker"] == "aegisscan"

        from websockets.sync.client import connect

        fresh_status, fresh_body = _request(
            f"{DJANGO_URL}/api/v1/auth/login/",
            method="POST",
            payload={"email": E2E_EMAIL, "password": E2E_PASSWORD},
        )
        assert fresh_status == 200, f"Fresh login for WebSocket failed: {fresh_status} {fresh_body}"
        ws_token = json.loads(fresh_body)["access"]

        with connect(
            "ws://127.0.0.1:8001/ws/workflow",
            subprotocols=["bearer", ws_token],
            open_timeout=10,
            close_timeout=5,
        ) as websocket:
            connected = json.loads(websocket.recv(timeout=5))
            assert connected["type"] == "workflow.connected"
            assert connected["user_id"]

            _bump_session_version()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    message = json.loads(websocket.recv(timeout=2))
                except TimeoutError:
                    continue
                assert message == {"type": "auth.revoked", "reason": "session_revoked"}
                break
            else:
                raise AssertionError("Timed out waiting for live auth.revoked event")

            try:
                websocket.recv(timeout=5)
            except Exception as exc:
                assert getattr(exc, "code", None) == 4001
                assert getattr(exc, "reason", "") == "Authentication revoked"
            else:
                raise AssertionError("WebSocket remained open after live revocation")
