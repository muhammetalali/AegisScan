from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from django_project.users.models import User

from fastapi_app.core import dependencies


def _request_with_cookie(cookie_value: str) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/api/v1/security/decision-pack",
        "raw_path": b"/api/v1/security/decision-pack",
        "query_string": b"",
        "headers": [(b"cookie", f"aegis_access={cookie_value}".encode("ascii"))],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 443),
    }
    return Request(scope)


def test_get_current_user_accepts_cookie_only_session(monkeypatch):
    seen: list[str] = []

    async def fake_verify_token(token: str):
        seen.append(token)
        return {"user_id": "cookie-user", "auth_version": 1, "token_type": "access"}

    async def fake_is_active_user(user_id: str, auth_version: int):
        return user_id == "cookie-user" and auth_version == 1

    monkeypatch.setattr(dependencies, "verify_token", fake_verify_token)
    monkeypatch.setattr(dependencies, "_is_active_user", fake_is_active_user)

    user = asyncio.run(
        dependencies.get_current_user(
            _request_with_cookie("cookie-access-token"),
            credentials=None,
        )
    )

    assert seen == ["cookie-access-token"]
    assert user["user_id"] == "cookie-user"


@pytest.mark.django_db(transaction=True)
def test_deactivated_employee_cookie_is_rejected_immediately(monkeypatch):
    employee = User.objects.create_user(
        email="deactivated-cookie-test@example.invalid",
        password="Strong-Test-Password-123!",
    )

    async def still_valid_signed_token(_token: str):
        return {"user_id": str(employee.pk), "auth_version": employee.auth_version, "token_type": "access"}

    monkeypatch.setattr(dependencies, "verify_token", still_valid_signed_token)
    request = _request_with_cookie("still-cryptographically-valid-token")
    identity = asyncio.run(dependencies.get_current_user(request, credentials=None))
    assert identity["user_id"] == str(employee.pk)

    employee.is_active = False
    employee.save(update_fields=["is_active"])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(dependencies.get_current_user(request, credentials=None))
    assert exc.value.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_unknown_or_invalid_signed_identity_is_denied(monkeypatch):
    async def signed_token_with_invalid_identity(_token: str):
        return {"user_id": "invalid-account-id", "auth_version": 1, "token_type": "access"}

    monkeypatch.setattr(dependencies, "verify_token", signed_token_with_invalid_identity)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(dependencies.get_current_user(
            _request_with_cookie("otherwise-valid-token"), credentials=None,
        ))
    assert exc.value.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_previous_generation_token_rejected_after_reactivation(monkeypatch):
    employee = User.objects.create_user(
        email="revoked-epoch-fastapi@example.invalid",
        password="Strong-Test-Password-123!",
    )
    old_generation = employee.auth_version

    async def signed_token(_token: str):
        return {
            "user_id": str(employee.pk),
            "auth_version": old_generation,
            "token_type": "access",
        }

    monkeypatch.setattr(dependencies, "verify_token", signed_token)
    request = _request_with_cookie("pre-revocation-signed-token")
    assert asyncio.run(dependencies.get_current_user(request, credentials=None))
    from django.db.models import F
    employee.is_active = False
    employee.save(update_fields=["is_active"])
    User.objects.filter(pk=employee.pk).update(auth_version=F("auth_version") + 1)
    employee.is_active = True
    employee.save(update_fields=["is_active"])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(dependencies.get_current_user(request, credentials=None))
    assert exc.value.status_code == 401


@pytest.mark.django_db(transaction=True)
def test_revoked_account_cannot_admit_fastapi_websocket_after_reactivation(monkeypatch):
    from fastapi_app import main as live_main
    from django_project.users.authentication import bump_auth_version

    employee = User.objects.create_user(
        email='fastapi-ws-revoked@example.invalid',
        password='Strong-Test-Password-123!',
    )
    generation = employee.auth_version

    async def verified_signature(_token):
        return {'user_id': str(employee.pk), 'auth_version': generation,
                'token_type': 'access'}

    monkeypatch.setattr(live_main, 'verify_token', verified_signature)

    class FakeWebSocket:
        cookies = {'aegis_access': 'synthetic-test-token'}
        def __init__(self):
            self.closes = []
        async def close(self, code):
            self.closes.append(code)

    valid = FakeWebSocket()
    assert asyncio.run(live_main._authenticate_socket(valid)) is not None
    assert valid.closes == []

    employee.is_active = False
    employee.save(update_fields=['is_active'])
    bump_auth_version(employee)
    employee.is_active = True
    employee.save(update_fields=['is_active'])
    revoked = FakeWebSocket()
    assert asyncio.run(live_main._authenticate_socket(revoked)) is None
    assert revoked.closes == [4001]


def test_websocket_broadcast_fails_closed_and_idle_stream_is_closed_on_revocation(
    monkeypatch,
):
    from fastapi_app import main as live_main
    from fastapi_app.services.websocket_manager import WebSocketManager

    active = {'value': True}

    async def current_generation(_user_id, version):
        return active['value'] and version == 7

    monkeypatch.setattr(live_main, '_is_active_user', current_generation)
    from fastapi_app.core import dependencies as auth_dependencies
    monkeypatch.setattr(auth_dependencies, '_is_active_user', current_generation)

    class FakeSocket:
        def __init__(self):
            self.accepts = 0
            self.sent = []
            self.closed = []
            self.recv = asyncio.Event()
        async def accept(self):
            self.accepts += 1
        async def send_json(self, payload):
            self.sent.append(payload)
        async def close(self, code):
            self.closed.append(code)
        async def receive_text(self):
            await self.recv.wait()
            return 'ping'

    async def verify():
        ws = FakeSocket()
        manager = WebSocketManager()
        identity = {'user_id': '175', 'auth_version': 7}
        await manager.connect('scan', ws, identity)
        await manager.connect('scan_1', ws, identity)
        assert ws.accepts == 1
        await manager.broadcast('scan', {'type': 'valid'})
        assert ws.sent == [{'type': 'valid'}]
        active['value'] = False
        await manager.broadcast('scan_1', {'type': 'should-not-leak'})
        assert ws.sent == [{'type': 'valid'}]
        assert ws.closed == [4001]
        assert manager.get_total_connections() == 0

        # Already admitted but idle sockets are checked even without a broadcast.
        active['value'] = True
        idle = FakeSocket()
        task = asyncio.create_task(live_main._receive_authorized_socket(idle, identity))
        await asyncio.sleep(0.05)
        active['value'] = False
        await asyncio.wait_for(task, timeout=3.0)
        assert idle.closed == [4001]
    asyncio.run(verify())
