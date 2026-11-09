"""Server-built anonymous GET /health and bounded result interpretation."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit


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


def safe_transport_metadata(payload: dict) -> dict:
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


def health_request_arguments(target: str) -> dict:
    p = urlsplit(target)
    if (p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password
            or p.path not in {'', '/'} or p.query or p.fragment
            or any(ord(c) < 33 for c in target)):
        raise ValueError('The BAC transport probe requires a credential-free web origin')
    port = p.port or (443 if p.scheme == 'https' else 80)
    hostname = p.hostname.encode('idna').decode('ascii')
    authority = f'[{hostname}]' if ':' in hostname else hostname
    default = 443 if p.scheme == 'https' else 80
    if port != default:
        authority += f':{port}'
    return {
        'targetHostname': hostname, 'targetPort': port, 'usesHttps': p.scheme == 'https',
        'content': f'GET /health HTTP/1.1\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n\r\n',
    }


def summarize_health_result(payload: dict) -> dict:
    """Never persist MCP text blocks, response headers, cookies, or raw bodies."""
    result = payload.get('mcp_result')
    content = result.get('content') if isinstance(result, dict) else None
    if (not isinstance(content, list) or len(content) != 1
            or not isinstance(content[0], dict) or content[0].get('type') != 'text'
            or not isinstance(content[0].get('text'), str)):
        raise ValueError('Burp returned no unambiguous HTTP response text')
    raw = content[0]['text']
    if len(raw.encode()) > 1_048_576:
        raise ValueError('Burp HTTP response exceeds the bounded probe limit')
    response_text = raw
    response_format = 'http-response'
    prefix = 'HttpRequestResponse{httpRequest='
    delimiter = ', httpResponse='
    suffix = ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
    if raw.startswith(prefix):
        if not raw.endswith(suffix) or raw.count(delimiter) != 1:
            raise ValueError('Burp returned an ambiguous request-response wrapper')
        request_text, _, response_text = raw[len(prefix):-len(suffix)].partition(delimiter)
        if (not request_text.startswith('GET /health HTTP/1.1\r\n')
                or request_text.count('\r\n\r\n') != 1
                or not request_text.endswith('\r\n\r\n')):
            raise ValueError('Burp returned a mismatched health request wrapper')
        response_format = 'montoya-request-response'
    head, sep, body = response_text.partition('\r\n\r\n')
    if not sep:
        head, sep, body = response_text.partition('\n\n')
    first = head.splitlines()[0] if head else ''
    parts = first.split(' ', 2)
    if not sep or len(parts) < 2 or parts[0] not in {'HTTP/1.0', 'HTTP/1.1', 'HTTP/2'} or not parts[1].isdigit():
        raise ValueError('Burp returned denied, empty or malformed HTTP output')
    status = int(parts[1])
    if not 100 <= status <= 599:
        raise ValueError('Burp returned an invalid HTTP status')
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    marker = bool(isinstance(data, dict) and data.get('fixture') == 'bac-target' and data.get('status') == 'ok')
    return {
        'transport_metadata': safe_transport_metadata(payload), 'status_code': status,
        'response_sha256': hashlib.sha256(raw.encode()).hexdigest(),
        'response_format': response_format,
        'fixture_health_marker_matches': marker, 'transport_probe_passed': status == 200 and marker,
        'live_fixture_revision_verified': False, 'lab_solved': False,
        'raw_request_response_persisted': False,
    }
