from fastapi.testclient import TestClient

from fastapi_app.main import app


def test_workflow_websocket_without_token_is_rejected_without_server_error():
    with TestClient(app) as client:
        try:
            with client.websocket_connect("/ws/workflow"):
                raise AssertionError("WebSocket without credentials must not connect")
        except Exception as exc:
            # Starlette's TestClient reports a handshake rejection as a
            # WebSocket denial response. The important invariant is that the
            # application must not raise an internal server error.
            assert "403" in str(exc) or "denial" in str(exc).lower()


def test_workflow_websocket_with_invalid_token_is_rejected():
    with TestClient(app) as client:
        try:
            with client.websocket_connect(
                "/ws/workflow",
                subprotocols=["bearer", "invalid-token"],
            ):
                raise AssertionError("Invalid JWT must not connect")
        except Exception as exc:
            assert "403" in str(exc) or "denial" in str(exc).lower()
