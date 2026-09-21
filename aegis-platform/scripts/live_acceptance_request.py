#!/usr/bin/env python3
"""Authorize a bounded live-acceptance run from manual dispatch or one-time main push."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,80}$")
SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
CONFIRM_RE = re.compile(r"^[A-Z0-9_-]{3,32}$")
MAIN_REF = "refs/heads/main"
SCHEMA = "aegisscan.live-acceptance-request.v1"
AUTH_SCHEMA = "aegisscan.live-acceptance-authorization.v1"
MAX_REQUEST_BYTES = 16 * 1024
MAX_LIFETIME = timedelta(hours=24)
CLOCK_SKEW = timedelta(minutes=5)
REQUIRED_FIELDS = {
    "schema", "request_id", "scope", "confirm", "requested_branch",
    "requested_base_sha", "requested_at", "expires_at",
}


class LiveAcceptanceRequestError(RuntimeError):
    pass


def _sha(value: str, label: str) -> str:
    value = value.strip().lower()
    if not SHA_RE.fullmatch(value):
        raise LiveAcceptanceRequestError(f"{label} must be exactly 40 lowercase hexadecimal characters")
    return value


def _utc(value: str, label: str) -> datetime:
    raw = value.strip()
    if not raw.endswith("Z"):
        raise LiveAcceptanceRequestError(f"{label} must be an explicit UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as exc:
        raise LiveAcceptanceRequestError(f"{label} is not a valid ISO-8601 timestamp") from exc
    return parsed.astimezone(timezone.utc)


def _load_request(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise LiveAcceptanceRequestError(f"live-acceptance request file does not exist: {path}")
    size = path.stat().st_size
    if size <= 0 or size > MAX_REQUEST_BYTES:
        raise LiveAcceptanceRequestError("live-acceptance request file has invalid size")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveAcceptanceRequestError(f"live-acceptance request is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise LiveAcceptanceRequestError("live-acceptance request must be a JSON object")
    fields = set(payload)
    if fields != REQUIRED_FIELDS:
        missing = sorted(REQUIRED_FIELDS - fields)
        unknown = sorted(fields - REQUIRED_FIELDS)
        raise LiveAcceptanceRequestError(
            f"live-acceptance request fields mismatch: missing={missing} unknown={unknown}"
        )
    return payload


def authorize(
    *,
    event_name: str,
    ref: str,
    current_sha: str,
    event_before: str,
    confirm: str,
    request_file: Path,
    scope: str,
    required_confirm: str,
    now: datetime | None = None,
) -> dict[str, object]:
    if ref != MAIN_REF:
        raise LiveAcceptanceRequestError("live acceptance is restricted to refs/heads/main")
    current_sha = _sha(current_sha, "current SHA")
    scope = scope.strip().lower()
    required_confirm = required_confirm.strip().upper()
    if not SCOPE_RE.fullmatch(scope):
        raise LiveAcceptanceRequestError("scope is invalid")
    if not CONFIRM_RE.fullmatch(required_confirm):
        raise LiveAcceptanceRequestError("required confirmation token is invalid")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)

    if event_name == "workflow_dispatch":
        if confirm != required_confirm:
            raise LiveAcceptanceRequestError(
                f"manual live acceptance requires confirm={required_confirm}"
            )
        return {
            "schema": AUTH_SCHEMA,
            "authorized": True,
            "authorization_mode": "workflow_dispatch",
            "scope": scope,
            "release_sha": current_sha,
        }

    if event_name != "push":
        raise LiveAcceptanceRequestError(f"unsupported live-acceptance event: {event_name}")

    before = _sha(event_before, "push before SHA")
    if before == current_sha:
        raise LiveAcceptanceRequestError("push before SHA must differ from current SHA")
    payload = _load_request(request_file)

    if payload["schema"] != SCHEMA:
        raise LiveAcceptanceRequestError("live-acceptance request schema mismatch")
    request_id = str(payload["request_id"])
    if not REQUEST_ID_RE.fullmatch(request_id):
        raise LiveAcceptanceRequestError("live-acceptance request id is invalid")
    if payload["scope"] != scope:
        raise LiveAcceptanceRequestError("live-acceptance request scope mismatch")
    if payload["confirm"] != required_confirm:
        raise LiveAcceptanceRequestError(
            f"live-acceptance request requires confirm={required_confirm}"
        )
    if payload["requested_branch"] != "main":
        raise LiveAcceptanceRequestError("live-acceptance request must target main")
    requested_base = _sha(str(payload["requested_base_sha"]), "requested base SHA")
    if requested_base != before:
        raise LiveAcceptanceRequestError(
            "live-acceptance request base SHA does not match the exact pre-push main SHA"
        )

    requested_at = _utc(str(payload["requested_at"]), "requested_at")
    expires_at = _utc(str(payload["expires_at"]), "expires_at")
    if requested_at > now + CLOCK_SKEW:
        raise LiveAcceptanceRequestError("live-acceptance request timestamp is in the future")
    if expires_at <= now:
        raise LiveAcceptanceRequestError("live-acceptance request has expired")
    if expires_at <= requested_at:
        raise LiveAcceptanceRequestError("live-acceptance request expiry must be after requested_at")
    if expires_at - requested_at > MAX_LIFETIME:
        raise LiveAcceptanceRequestError("live-acceptance request lifetime exceeds 24 hours")

    return {
        "schema": AUTH_SCHEMA,
        "authorized": True,
        "authorization_mode": "one-time-main-push",
        "scope": scope,
        "request_id": request_id,
        "requested_base_sha": requested_base,
        "release_sha": current_sha,
        "expires_at": payload["expires_at"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--current-sha", required=True)
    parser.add_argument("--event-before", default="")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--required-confirm", required=True)
    args = parser.parse_args()
    try:
        result = authorize(
            event_name=args.event_name,
            ref=args.ref,
            current_sha=args.current_sha,
            event_before=args.event_before,
            confirm=args.confirm,
            request_file=args.request_file,
            scope=args.scope,
            required_confirm=args.required_confirm,
        )
    except LiveAcceptanceRequestError as exc:
        print(
            json.dumps({"schema": AUTH_SCHEMA, "authorized": False, "error": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
