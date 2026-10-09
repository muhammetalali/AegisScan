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
        return {"user_id": "cookie-user", "token_type": "access"}

    async def fake_is_active_user(user_id: str):
        return user_id == "cookie-user"

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
        return {"user_id": str(employee.pk), "token_type": "access"}

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
        return {"user_id": "invalid-account-id", "token_type": "access"}

    monkeypatch.setattr(dependencies, "verify_token", signed_token_with_invalid_identity)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(dependencies.get_current_user(
            _request_with_cookie("otherwise-valid-token"), credentials=None,
        ))
    assert exc.value.status_code == 401
