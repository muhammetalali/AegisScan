"""Fail-closed, non-executing HTTP authentication/OTP observation contract.

This is a pure validation component for a future governed Burp Web Lab adapter.
It does not send requests, authorize assets/providers, open browser sessions,
handle credentials, create DB rows, or assert a remote lab is solved.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import re
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

_BODY_LIMIT = 65_536
_PATH_RE = re.compile(r"/[A-Za-z0-9._~/-]{0,510}")
_STAGES = frozenset({"login_form", "primary_login", "otp_submit", "protected_fetch"})
_AUTH_JSON_STEPS = frozenset({"primary_login", "otp_submit"})


class AuthLabContractError(ValueError):
    """Invalid control-plane or target response: no network side effects."""


class Stage(str, Enum):
    ANONYMOUS = "anonymous"
    LOGIN_SEEN = "login_seen"
    OTP_PENDING = "otp_pending"
    OTP_VERIFIED = "otp_verified"
    PROTECTED_OBSERVED = "protected_observed"


@dataclass(frozen=True)
class AuthAttempt:
    """Never contains cookies, tokens, credentials or raw HTTP response bodies."""
    attempt_ref: str
    authorized_origin: str
    stage: Stage = Stage.ANONYMOUS
    session_binding_ref: str | None = None
    next_path: str | None = None
    observations: int = 0
    max_observations: int = 25

    def __post_init__(self) -> None:
        try:
            if str(UUID(self.attempt_ref)) != self.attempt_ref:
                raise ValueError("Noncanonical attempt id")
        except (TypeError, AttributeError, ValueError) as exc:
            raise AuthLabContractError("An authoritative attempt UUID is required.") from exc
        if not isinstance(self.stage, Stage):
            raise AuthLabContractError("Unrecognized authentication stage.")
        _scope(self.authorized_origin)
        if not (type(self.max_observations) is int and 1 <= self.max_observations <= 25
                and type(self.observations) is int
                and 0 <= self.observations <= self.max_observations):
            raise AuthLabContractError("Authentication attempt budget is invalid.")
        if self.session_binding_ref is not None:
            _binding_ref(self.session_binding_ref)
        if self.next_path is not None:
            _approved_path(self.next_path)


def _scope(origin: str) -> tuple[str, str, int]:
    if (not isinstance(origin, str) or len(origin) > 300 or any(ord(ch) < 33 for ch in origin)):
        raise AuthLabContractError("Authorized HTTPS origin is required.")
    try:
        parsed = urlsplit(origin)
        port = parsed.port or 443
    except ValueError as exc:
        raise AuthLabContractError("Authorized origin is malformed.") from exc
    if (parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.isascii()
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or port != 443
            or not re.fullmatch(r"[a-z0-9.-]{1,253}", parsed.hostname)
            or any(x in parsed.hostname for x in ("..",))):
        raise AuthLabContractError("Only the exact approved HTTPS origin is accepted.")
    return parsed.scheme, parsed.hostname.lower(), port


def _approved_path(value: str) -> str:
    if (not isinstance(value, str) or not _PATH_RE.fullmatch(value)
            or "//" in value or any(segment in {".", ".."} for segment in value.split("/"))):
        raise AuthLabContractError("Redirect path is not a safe bounded application path.")
    return value


def _redirect_path(value: Any, origin: str) -> str:
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 for c in value):
        raise AuthLabContractError("Server redirect is invalid.")
    if value.startswith("/"):
        return _approved_path(value)
    parsed = urlsplit(value)
    if _scope(origin) != (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or 443):
        raise AuthLabContractError("Server redirect escapes the approved origin.")
    if (parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise AuthLabContractError("Server redirect contains unsupported credentials or query.")
    return _approved_path(parsed.path or "/")


def _binding_ref(value: str) -> str:
    # Metadata for the worker-controlled browser/session context, not a cookie.
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError("Invalid binding UUID")
    except (TypeError, ValueError, AttributeError) as exc:
        raise AuthLabContractError("A canonical, worker-bound session reference is required.") from exc
    return value


def _json_reply(data: bytes) -> dict:
    if not isinstance(data, bytes) or len(data) > _BODY_LIMIT:
        raise AuthLabContractError("Bounded byte response is required.")
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
        out = {}
        for key, value in pairs:
            if key in out:
                raise AuthLabContractError("Duplicate JSON field in authentication response.")
            out[key] = value
        return out
    def reject_nonfinite(_value: str) -> None:
        raise AuthLabContractError("Non-finite JSON values are forbidden.")

    try:
        reply = json.loads(
            data.decode("utf-8"), object_pairs_hook=unique_pairs,
            parse_constant=reject_nonfinite,
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthLabContractError("Authentication response is not strict JSON.") from exc
    if not isinstance(reply, dict):
        raise AuthLabContractError("Authentication response must be a JSON object.")
    return reply


def observe(
    attempt: AuthAttempt, *, step: str, http_status: int,
    body: bytes, session_binding_ref: str | None = None,
    request_path: str | None = None,
) -> tuple[AuthAttempt, dict]:
    """Evaluate one trusted worker observation, without any HTTP or DB write.

    Valid stages: login_form → primary_login → otp_submit → protected_fetch.
    A protected page HTTP 200 is only an observation, never proof of lab solved.
    """
    if not isinstance(attempt, AuthAttempt):
        raise AuthLabContractError("An existing governed attempt is required.")
    if step not in _STAGES or not isinstance(step, str):
        raise AuthLabContractError("Unknown or unsupported authentication step.")
    if type(http_status) is not int or not 100 <= http_status <= 599:
        raise AuthLabContractError("Invalid HTTP response status.")
    if not isinstance(body, bytes) or len(body) > _BODY_LIMIT:
        raise AuthLabContractError("Response body exceeds its bounded limit.")
    if attempt.observations >= attempt.max_observations:
        raise AuthLabContractError("Authentication attempt budget has been exhausted.")
    expected = {
        "login_form": Stage.ANONYMOUS,
        "primary_login": Stage.LOGIN_SEEN,
        "otp_submit": Stage.OTP_PENDING,
        "protected_fetch": Stage.OTP_VERIFIED,
    }[step]
    if attempt.stage != expected:
        raise AuthLabContractError("Authentication step violates the bound state machine.")

    binding = None
    if step in {"primary_login", "otp_submit", "protected_fetch"}:
        binding = _binding_ref(session_binding_ref)
        if attempt.session_binding_ref is not None and attempt.session_binding_ref != binding:
            raise AuthLabContractError("Cross-session or stale MFA observation.")
    if step == "protected_fetch":
        if request_path is None or _approved_path(request_path) != attempt.next_path:
            raise AuthLabContractError("Protected page must be the verified server-issued redirect.")
    elif request_path is not None:
        raise AuthLabContractError("Client supplied a non-allowlisted request path.")

    result = "indeterminate"
    following_stage = attempt.stage
    following_path = attempt.next_path
    if step == "login_form":
        if http_status == 200 and b"<form" in body[:_BODY_LIMIT].lower():
            result, following_stage = "login_form_observed", Stage.LOGIN_SEEN
    elif step in _AUTH_JSON_STEPS:
        reply = _json_reply(body)
        if http_status in range(200, 300) and reply.get("ok") is True:
            following_path = _redirect_path(reply.get("redirect"), attempt.authorized_origin)
            result = "stage_transition_observed"
            following_stage = Stage.OTP_PENDING if step == "primary_login" else Stage.OTP_VERIFIED
        elif 400 <= http_status < 500 or reply.get("ok") is False:
            result = "denied"
    elif step == "protected_fetch":
        if http_status == 200:
            result, following_stage = "protected_response_observed", Stage.PROTECTED_OBSERVED
        elif 300 <= http_status < 500:
            result = "denied"

    new = replace(
        attempt, stage=following_stage,
        session_binding_ref=(
            attempt.session_binding_ref or (
                binding if following_stage in {
                    Stage.OTP_PENDING, Stage.OTP_VERIFIED, Stage.PROTECTED_OBSERVED
                } else None
            )
        ),
        next_path=following_path,
        observations=attempt.observations + 1,
    )
    return new, {
        "schema": "aegis.web-lab-auth-observation.v1",
        "attempt_ref": attempt.attempt_ref,
        "step": step, "status_code": http_status,
        "result": result, "stage_after": new.stage.value,
        "response_sha256": hashlib.sha256(body).hexdigest(),
        "raw_response_persisted": False,
        "lab_solved": False,
        "independent_success_screen_proven": False,
    }
