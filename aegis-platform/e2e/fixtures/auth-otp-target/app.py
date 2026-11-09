"""Isolated, synthetic authentication/MFA fixture (never a public target).

Two explicit variants test whether a protected route requires the OTP stage.
Use with FastAPI TestClient in CI; no service or credential is deployed.
"""
from __future__ import annotations

import secrets

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

_SYNTHETIC_USER = "local-tester"
_SYNTHETIC_PASSWORD = "local-lab-secret"
_SYNTHETIC_OTP = "246810"
_SUCCESS = "<!doctype html><title>Fixture success</title><h1>LOCAL_FIXTURE_SUCCESS</h1>"


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class OTP(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^[0-9]{6}$")


def create_app(variant: str) -> FastAPI:
    """No environment-dependent weak-mode toggle; select variant explicitly."""
    if variant not in {"vulnerable", "patched"}:
        raise ValueError("Unknown synthetic fixture variant")
    app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
    sessions: dict[str, dict[str, bool]] = {}

    def session(request: Request) -> dict[str, bool] | None:
        key = request.cookies.get("fixture_sid")
        return sessions.get(key) if key else None

    @app.get("/health")
    def health():
        return {"fixture": "auth-otp-target", "variant": variant, "status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    def login_form():
        return "<!doctype html><form id='loginForm'><input name='username'><input name='password'></form>"

    @app.post("/api/login")
    def login(payload: Login):
        if payload.username != _SYNTHETIC_USER or payload.password != _SYNTHETIC_PASSWORD:
            return JSONResponse({"ok": False, "message": "invalid login"}, status_code=401)
        if len(sessions) >= 25:
            return JSONResponse({"ok": False, "message": "fixture session limit"}, status_code=429)
        sid = secrets.token_urlsafe(24)
        sessions[sid] = {"primary": True, "otp": False}
        response = JSONResponse({"ok": True, "redirect": "/otp"})
        response.set_cookie(
            "fixture_sid", sid, httponly=True, secure=True, samesite="strict",
            path="/", max_age=900,
        )
        return response

    @app.get("/otp")
    def otp_form(request: Request):
        if not session(request):
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse("<!doctype html><form id='otpForm'><input name='code'></form>")

    @app.post("/api/otp")
    def otp(payload: OTP, request: Request):
        active = session(request)
        if not active or not active["primary"]:
            return JSONResponse({"ok": False, "message": "login required"}, status_code=403)
        if payload.code != _SYNTHETIC_OTP:
            return JSONResponse({"ok": False, "message": "invalid verification"}, status_code=401)
        active["otp"] = True
        return JSONResponse({"ok": True, "redirect": "/protected"})

    @app.get("/protected")
    def protected(request: Request):
        active = session(request)
        if not active or not active["primary"]:
            return JSONResponse({"ok": False, "message": "login required"}, status_code=401)
        # This single difference models the vulnerability under examination.
        if variant == "patched" and not active["otp"]:
            return JSONResponse({"ok": False, "message": "OTP required"}, status_code=403)
        return HTMLResponse(_SUCCESS, headers={"Cache-Control": "no-store"})

    return app
