from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from fastapi_app.main import app


def test_workflow_websocket_without_token_is_rejected_without_server_error():
    with TestClient(app) as client:
        try:
            with client.websocket_connect("/ws/workflow"):
                raise AssertionError("WebSocket without credentials must not connect")
        except WebSocketDisconnect as exc:
            # The application rejects unauthenticated clients with an
            # application-level close code rather than raising HTTP 500.
            assert exc.code == 4001


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
