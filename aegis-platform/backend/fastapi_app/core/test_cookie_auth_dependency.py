from __future__ import annotations

import asyncio

from starlette.requests import Request

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

    monkeypatch.setattr(dependencies, "verify_token", fake_verify_token)

    user = asyncio.run(
        dependencies.get_current_user(
            _request_with_cookie("cookie-access-token"),
            credentials=None,
        )
    )

    assert seen == ["cookie-access-token"]
    assert user["user_id"] == "cookie-user"
