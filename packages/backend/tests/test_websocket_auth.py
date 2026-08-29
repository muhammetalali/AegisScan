import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from django.contrib.auth import get_user_model

from fastapi_app.core.config import settings
from fastapi_app.main import app
from users.auth_security import AegisTokenObtainPairSerializer


@pytest.mark.django_db
def test_workflow_websocket_without_token_is_rejected_without_server_error():
    with TestClient(app) as client:
        try:
            with client.websocket_connect("/ws/workflow"):
                raise AssertionError("WebSocket without credentials must not connect")
        except WebSocketDisconnect as exc:
            # The application rejects unauthenticated clients with an
            # application-level close code rather than raising HTTP 500.
            assert exc.code == 4001


@pytest.mark.django_db
def test_workflow_websocket_with_invalid_token_is_rejected():
    with TestClient(app) as client:
        try:
            with client.websocket_connect(
                "/ws/workflow",
                subprotocols=["bearer", "invalid-token"],
            ):
                raise AssertionError("Invalid JWT must not connect")
        except WebSocketDisconnect as exc:
            assert exc.code == 4001


@pytest.mark.django_db
def test_workflow_websocket_is_revoked_after_session_version_bump(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "WS_SESSION_CHECK_INTERVAL_SECONDS", 1)

    User = get_user_model()
    user = User.objects.create_user(
        email="ws-live-revocation@local.test",
        password="Ws-Live-Revocation-2026!x9",
        role="security_analyst",
        is_active=True,
        is_verified=True,
    )
    token = str(AegisTokenObtainPairSerializer.get_token(user).access_token)
    original_version = user.session_version

    with TestClient(app) as client:
        with client.websocket_connect(
            "/ws/workflow",
            subprotocols=["bearer", token],
        ) as websocket:
            connected = websocket.receive_json()
            assert connected["type"] == "workflow.connected"
            assert connected["user_id"] == str(user.id)

            user.session_version = original_version + 1
            user.save(update_fields=["session_version"])

            revoked = websocket.receive_json()
            assert revoked == {
                "type": "auth.revoked",
                "reason": "session_revoked",
            }

            deadline = time.monotonic() + 2
            with pytest.raises(WebSocketDisconnect) as exc_info:
                websocket.receive_text()
            assert exc_info.value.code == 4001
            assert time.monotonic() <= deadline
