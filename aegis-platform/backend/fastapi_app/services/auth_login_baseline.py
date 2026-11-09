"""Server-built, anonymous GET /login probe for governed Burp MCP sessions.

No client-provided path/body/headers, no credentials, no raw response persistence.
This is NOT an auth/MFA solver and never infers that a protected page was reached.
"""
from __future__ import annotations

import hashlib
import re

from .burp_http_probe import health_request_arguments

AUTH_BASELINE_ID = "auth-login-baseline-v1"
AUTH_BASELINE_PATH = "/login"
_HTTP_STATUS = re.compile(r"^HTTP/(?:1\.0|1\.1|2) ([1-5][0-9]{2})(?: .*)?$")


# These are the only transport diagnostics admitted to durable evidence. Treat
# even the MCP adapter result as untrusted at the evidence serialization edge.
# The "contract-*" values are synthetic offline test transports, never a trust
# or provider approval signal.
_TRANSPORTS = frozenset({"sse", "sse-unix", "contract-only", "contract-double"})
_METADATA_KEYS = frozenset({
    "transport", "protocol_version", "server_info_sha256", "server_name",
    "server_reported_version", "tools_sha256", "tool_schema_sha256",
    "edition", "retry_count",
})
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^(?:[0-9]{1,4}\.){2}[0-9]{1,4}$")


def _safe_transport_metadata(payload: dict) -> dict:
    metadata = payload.get("transport_metadata")
    if not isinstance(metadata, dict) or set(metadata) - _METADATA_KEYS:
        raise ValueError("Unexpected or unbounded MCP transport metadata.")
    if (not isinstance(metadata.get("transport"), str)
            or metadata["transport"] not in _TRANSPORTS):
        raise ValueError("Unrecognized MCP transport.")
    safe = {"transport": metadata["transport"]}
    for name in ("server_info_sha256", "tools_sha256", "tool_schema_sha256"):
        if name in metadata:
            value = metadata[name]
            if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
                raise ValueError("Malformed MCP transport digest.")
            safe[name] = value
    if "protocol_version" in metadata:
        if metadata["protocol_version"] != "2024-11-05":
            raise ValueError("Unexpected MCP protocol version.")
        safe["protocol_version"] = metadata["protocol_version"]
    if "server_name" in metadata:
        if metadata["server_name"] not in ("burp-suite", "unrecognized"):
            raise ValueError("Unexpected MCP server name.")
        safe["server_name"] = metadata["server_name"]
    if "server_reported_version" in metadata:
        value = metadata["server_reported_version"]
        if (not isinstance(value, str)
                or (value != "not_reported" and not _VERSION_RE.fullmatch(value))):
            raise ValueError("Unexpected MCP server version.")
        safe["server_reported_version"] = value
    if "edition" in metadata:
        if metadata["edition"] != "not_reported":
            raise ValueError("Unverified MCP product edition.")
        safe["edition"] = "not_reported"
    if "retry_count" in metadata:
        if type(metadata["retry_count"]) is not int or metadata["retry_count"] != 0:
            raise ValueError("MCP probe must never report an automatic retry.")
        safe["retry_count"] = 0
    return safe


def login_request_arguments(target: str) -> dict:
    """Reuse the pinned web-origin validator and server-generated wire request."""
    base = health_request_arguments(target)
    wire = base["content"]
    old = "GET /health HTTP/1.1\r\n"
    if not wire.startswith(old):
        raise ValueError("Server-origin transport contract changed.")
    wire = "GET /login HTTP/1.1\r\n" + wire[len(old):]
    wire = wire.replace("Accept: application/json\r\n", "Accept: text/html\r\n", 1)
    if not wire.endswith("\r\n\r\n"):
        raise ValueError("Malformed bounded HTTP request.")
    return {**base, "content": wire}


def summarize_login_result(payload: dict, *, request_arguments: dict) -> dict:
    """Validate exact response binding and return redacted observation metadata."""
    if not isinstance(payload, dict):
        raise ValueError("Bounded MCP response is required.")
    transport = _safe_transport_metadata(payload)
    result = payload.get("mcp_result")
    blocks = result.get("content") if isinstance(result, dict) else None
    if (not isinstance(blocks, list) or len(blocks) != 1 or
            not isinstance(blocks[0], dict) or blocks[0].get("type") != "text" or
            not isinstance(blocks[0].get("text"), str)):
        raise ValueError("Missing or ambiguous MCP HTTP response block.")
    raw = blocks[0]["text"]
    if len(raw.encode("utf-8")) > 1_048_576:
        raise ValueError("Login response exceeds one MiB.")
    expected_request = request_arguments.get("content")
    if (not isinstance(expected_request, str)
            or not expected_request.startswith("GET /login HTTP/1.1\r\n")):
        raise ValueError("Missing server-built login request binding.")
    response = raw
    if raw.startswith("HttpRequestResponse{"):
        prefix = "HttpRequestResponse{httpRequest=" + expected_request + ", httpResponse="
        suffix = ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
        if not raw.startswith(prefix) or not raw.endswith(suffix):
            raise ValueError("Burp result does not bind the exact governed request.")
        response = raw[len(prefix):-len(suffix)]
    head, delimiter, body = response.partition("\r\n\r\n")
    if not delimiter:
        head, delimiter, body = response.partition("\n\n")
    if not delimiter or len(head) > 65_536:
        raise ValueError("Malformed or unbounded HTTP response headers.")
    status_line = head.splitlines()[0] if head else ""
    match = _HTTP_STATUS.fullmatch(status_line)
    if not match:
        raise ValueError("Invalid HTTP status line.")
    code = int(match.group(1))
    # A Login form being present is public application surface, never a finding.
    form_seen = code == 200 and b"<form" in body.encode("utf-8", "replace").lower()
    return {
        "schema": "aegis.auth-login-baseline-observation.v1",
        "definition_id": AUTH_BASELINE_ID,
        "method": "GET",
        "path": AUTH_BASELINE_PATH,
        "status_code": code,
        "login_form_observed": form_seen,
        "transport_metadata": transport,
        "wire_request_sha256": hashlib.sha256(expected_request.encode()).hexdigest(),
        "response_sha256": hashlib.sha256(response.encode()).hexdigest(),
        "raw_request_response_persisted": False,
        "lab_solved": False,
        "mfa_bypassed": False,
        "success_screen_proven": False,
    }
