from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = ROOT / "packages" / "backend"
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:5173")
DJANGO_URL = os.getenv("DJANGO_URL", "http://127.0.0.1:8000")

EMAIL = os.getenv("FRONTEND_E2E_EMAIL", "frontend-backend-e2e@local.test")
PASSWORD = os.getenv("FRONTEND_E2E_PASSWORD", "Frontend-Backend-E2E-2026!x9")
ROLE = os.getenv("FRONTEND_E2E_ROLE", "security_analyst")


def _django_shell(command: str) -> str:
    env = os.environ.copy()
    env.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
    result = subprocess.run(
        [sys.executable, "manage.py", "shell", "-c", command],
        cwd=BACKEND_DIR,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def _wait(url: str, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                return
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(2)
    raise AssertionError(f"Timed out waiting for {url}: {last_error}")


def _ensure_user() -> None:
    values = {
        "email": EMAIL.replace("'", "\\'"),
        "password": PASSWORD.replace("'", "\\'"),
        "role": ROLE.replace("'", "\\'"),
    }
    command = (
        "from django.contrib.auth import get_user_model; "
        "User=get_user_model(); "
        f"u,_=User.objects.update_or_create(email='{values['email']}', defaults={{"
        f"'role':'{values['role']}','is_active':True,'is_verified':True"
        "}); "
        f"u.set_password('{values['password']}'); u.save(update_fields=['password']); "
        "print(u.email)"
    )
    _django_shell(command)


def _bump_session_version() -> None:
    escaped_email = EMAIL.replace("'", "\\'")
    _django_shell(
        "from django.contrib.auth import get_user_model; "
        "User=get_user_model(); "
        f"u=User.objects.get(email='{escaped_email}'); "
        "u.session_version += 1; "
        "u.save(update_fields=['session_version']); "
        "print(u.session_version)"
    )


def _delete_user() -> None:
    escaped_email = EMAIL.replace("'", "\\'")
    try:
        _django_shell(
            "from django.contrib.auth import get_user_model; "
            "User=get_user_model(); "
            f"print(User.objects.filter(email='{escaped_email}').delete()[0])"
        )
    except subprocess.CalledProcessError:
        pass


def test_frontend_backend_runtime_contract() -> None:
    """Prove the built frontend reverse-proxies auth, API and WebSocket correctly."""
    _wait(f"{FRONTEND_URL}/health")
    _wait(f"{DJANGO_URL}/health/")
    _ensure_user()
    try:
        session = requests.Session()

        login = session.post(
            f"{FRONTEND_URL}/api/v1/auth/login/",
            json={"email": EMAIL, "password": PASSWORD},
            timeout=10,
        )
        assert login.status_code == 200, login.text
        login_body = login.json()
        access = login_body["access"]
        refresh = login_body["refresh"]

        headers = {"Authorization": f"Bearer {access}"}
        fastapi = session.get(
            f"{FRONTEND_URL}/api/v1/assurance/correlations/summary",
            headers=headers,
            timeout=10,
        )
        assert fastapi.status_code == 200, fastapi.text
        assert {"conflicts", "signals", "sources", "agreement", "confidence"} <= set(fastapi.json())

        refreshed = session.post(
            f"{FRONTEND_URL}/api/v1/auth/refresh/",
            json={"refresh": refresh},
            timeout=10,
        )
        assert refreshed.status_code == 200, refreshed.text
        refreshed_access = refreshed.json()["access"]

        ws_url = FRONTEND_URL.replace("http://", "ws://").replace("https://", "wss:") + "/ws/workflow"
        with connect(
            ws_url,
            subprotocols=["bearer", refreshed_access],
            open_timeout=10,
            close_timeout=5,
        ) as websocket:
            connected = json.loads(websocket.recv(timeout=5))
            assert connected["type"] == "workflow.connected"

            _bump_session_version()

            revoked = json.loads(websocket.recv(timeout=10))
            assert revoked == {"type": "auth.revoked", "reason": "session_revoked"}

            try:
                websocket.recv(timeout=5)
                raise AssertionError("WebSocket remained open after auth.revoked")
            except ConnectionClosed as exc:
                assert exc.code == 4001, f"Unexpected WebSocket close code: {exc.code}"
                assert exc.reason == "Authentication revoked"
    finally:
        _delete_user()
