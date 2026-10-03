"""Server-built anonymous GET /health and bounded result interpretation."""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit


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
    head, sep, body = raw.partition('\r\n\r\n')
    if not sep:
        head, sep, body = raw.partition('\n\n')
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
        'transport_metadata': payload['transport_metadata'], 'status_code': status,
        'response_sha256': hashlib.sha256(raw.encode()).hexdigest(),
        'fixture_health_marker_matches': marker, 'transport_probe_passed': status == 200 and marker,
        'live_fixture_revision_verified': False, 'lab_solved': False,
        'raw_request_response_persisted': False,
    }
