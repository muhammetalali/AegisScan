from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit

_PARAMETER_CALL_RE = re.compile(
    r"""(?ix)
    \b(?:searchParams|queryParams|urlParams|params|formData)
    \s*\.\s*(?:get|set|append|has|delete)
    \s*\(\s*['"](?P<name>[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,79})['"]
    """
)
_QUERY_NAME_RE = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,79})=""")
_URL_LITERAL_RE = re.compile(
    r"""(?x)
    (?P<quote>['"])
    (?P<url>(?:https?://|/|\./|\.\./)[^'"\\\s]{1,512})
    (?P=quote)
    """
)
_SAFE_PARAMETER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,79}$')
_SENSITIVE_PROBE_RE = re.compile(
    r'(?:password|passwd|secret|token|auth|session|csrf|xsrf|otp|credential|api[_-]?key|logout|signout)',
    re.IGNORECASE,
)
_STATEFUL_PATH_RE = re.compile(
    r'/(?:logout|signout|delete|remove|destroy|revoke|reset|purchase|payment|checkout|transfer)(?:/|$)',
    re.IGNORECASE,
)


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme not in {'http', 'https'} or not host:
        return ''
    try:
        port = parsed.port
    except ValueError:
        return ''
    default = 80 if scheme == 'http' else 443
    authority = host if port in {None, default} else f'{host}:{port}'
    return urlunsplit((scheme, authority, '', '', ''))


def _canonical_url(value: str, *, base: str) -> str:
    raw = urljoin(base, value)
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ''
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme not in {'http', 'https'} or not host:
        return ''
    if parsed.username is not None or parsed.password is not None:
        return ''
    try:
        port = parsed.port
    except ValueError:
        return ''
    default = 80 if scheme == 'http' else 443
    authority = host if port in {None, default} else f'{host}:{port}'
    path = parsed.path or '/'
    query_names = sorted({
        name
        for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        if _SAFE_PARAMETER_RE.fullmatch(name)
    })
    query = '&'.join(f'{quote(name, safe="[]_.-")}=*' for name in query_names[:64])
    return urlunsplit((scheme, authority, path[:2048], query, ''))


def analyze_javascript_source(
    source: str,
    *,
    script_url: str,
    target_origin: str,
    max_parameters: int = 128,
    max_endpoints: int = 128,
) -> dict[str, Any]:
    """Extract redacted recon metadata from one already-captured same-origin JS body.

    This function is intentionally network-free. It never returns source snippets or
    literal parameter values.
    """
    if _origin(script_url) != target_origin:
        return {'parameter_names': [], 'endpoint_candidates': []}

    parameter_names: set[str] = set()
    endpoint_candidates: set[str] = set()

    for match in _PARAMETER_CALL_RE.finditer(source):
        parameter_names.add(match.group('name'))
        if len(parameter_names) >= max_parameters:
            break

    if len(parameter_names) < max_parameters:
        for match in _QUERY_NAME_RE.finditer(source):
            parameter_names.add(match.group(1))
            if len(parameter_names) >= max_parameters:
                break

    for match in _URL_LITERAL_RE.finditer(source):
        candidate = _canonical_url(match.group('url'), base=script_url)
        if not candidate or _origin(candidate) != target_origin:
            continue
        endpoint_candidates.add(candidate)
        for name, _ in parse_qsl(urlsplit(candidate).query, keep_blank_values=True):
            if _SAFE_PARAMETER_RE.fullmatch(name):
                parameter_names.add(name)
        if len(endpoint_candidates) >= max_endpoints:
            break

    return {
        'parameter_names': sorted(parameter_names)[:max_parameters],
        'endpoint_candidates': sorted(endpoint_candidates)[:max_endpoints],
    }


def build_hidden_parameter_probe_plan(
    endpoint_urls: list[str],
    parameter_names: list[str],
    *,
    target_origin: str,
    max_requests: int,
    max_parameters_per_endpoint: int = 4,
) -> list[dict[str, Any]]:
    """Build a HEAD-only plan whose exact HTTP request count cannot exceed max_requests.

    One baseline HEAD is budgeted per endpoint plus one HEAD for each candidate.
    Existing query names, sensitive names, and state-changing paths are excluded.
    """
    if max_requests < 2:
        return []

    safe_parameters = [
        name
        for name in sorted(set(parameter_names))
        if _SAFE_PARAMETER_RE.fullmatch(name)
        and not _SENSITIVE_PROBE_RE.search(name)
    ]
    if not safe_parameters:
        return []

    remaining = int(max_requests)
    plan: list[dict[str, Any]] = []
    seen_endpoints: set[str] = set()

    for raw in endpoint_urls:
        if remaining < 2:
            break
        try:
            parsed = urlsplit(raw)
        except ValueError:
            continue
        if _origin(raw) != target_origin or parsed.scheme not in {'http', 'https'}:
            continue
        base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', '', ''))
        if base in seen_endpoints or _STATEFUL_PATH_RE.search(parsed.path or '/'):
            continue
        seen_endpoints.add(base)

        existing = {
            name
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if _SAFE_PARAMETER_RE.fullmatch(name)
        }
        candidates = [name for name in safe_parameters if name not in existing]
        if not candidates:
            continue

        # A baseline request costs one; every parameter probe costs one.
        budget_for_candidates = min(
            max_parameters_per_endpoint,
            len(candidates),
            remaining - 1,
        )
        if budget_for_candidates <= 0:
            break
        selected = candidates[:budget_for_candidates]
        plan.append({'endpoint': base, 'parameter_names': selected})
        remaining -= 1 + len(selected)

    return plan


def probe_plan_request_count(plan: list[dict[str, Any]]) -> int:
    return sum(
        1 + len(item.get('parameter_names') or [])
        for item in plan
        if isinstance(item, dict)
    )
