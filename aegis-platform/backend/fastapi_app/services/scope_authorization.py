from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
from urllib.parse import urlsplit


class ScopeAuthorizationError(ValueError):
    """Raised when a target is not explicitly authorized for security execution."""


_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f\s]')


def _configured_targets() -> list[str]:
    raw = os.getenv('AUTHORIZED_SCAN_TARGETS', '')
    return [item.strip() for item in raw.split(',') if item.strip()]


def _canonical_hostname(value: str, *, require_http_scheme: bool = False) -> str:
    candidate = str(value).strip()
    if not candidate or _CONTROL_RE.search(candidate):
        raise ScopeAuthorizationError('Target contains whitespace or control characters')
    parsed = urlsplit(candidate if '://' in candidate else f'//{candidate}')
    if parsed.scheme and parsed.scheme.lower() not in {'http', 'https'}:
        raise ScopeAuthorizationError('Unsupported target scheme')
    if require_http_scheme and parsed.scheme.lower() not in {'http', 'https'}:
        raise ScopeAuthorizationError('URL scan targets require http or https')
    if parsed.username is not None or parsed.password is not None:
        raise ScopeAuthorizationError('Target userinfo is not allowed')
    if parsed.fragment:
        raise ScopeAuthorizationError('Target fragments are not allowed')
    if parsed.path not in {'', '/'} and parsed.scheme == '':
        raise ScopeAuthorizationError('Host targets cannot contain a path')
    host = parsed.hostname
    if not host:
        raise ScopeAuthorizationError('Target hostname is missing')
    host = host.rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        try:
            return host.encode('idna').decode('ascii').lower().rstrip('.')
        except UnicodeError as exc:
            raise ScopeAuthorizationError('Target hostname is not valid IDNA') from exc


def _canonical_entry(entry: str) -> tuple[str, bool]:
    value = entry.strip()
    if not value or _CONTROL_RE.search(value):
        raise ScopeAuthorizationError('Configured authorization contains invalid characters')
    if value in {'*', '**', '*.*'} or value.startswith('?.'):
        raise ScopeAuthorizationError('Global wildcard authorization is forbidden')
    try:
        return str(ipaddress.ip_network(value, strict=False)), True
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_address(value)), True
    except ValueError:
        pass
    normalized = value.lower().strip('.')
    if '*' in normalized or '?' in normalized:
        if not normalized.startswith('*.') or normalized.count('*') != 1 or '?' in normalized:
            raise ScopeAuthorizationError('Only a single left-most wildcard label is supported')
        normalized = normalized[2:]
    try:
        normalized = normalized.encode('idna').decode('ascii').lower().strip('.')
    except UnicodeError as exc:
        raise ScopeAuthorizationError('Configured hostname is not valid IDNA') from exc
    if not normalized or '.' not in normalized:
        raise ScopeAuthorizationError('Bare or ambiguous hostname authorization is forbidden')
    return normalized, False


def is_target_authorized(target: str) -> bool:
    """Match a target against the explicit server-side authorization allow-list.

    The match is fail-closed. Supported entries are exact IPs, CIDRs, exact
    DNS names, and a single left-most DNS wildcard such as ``*.example.com``.
    Global wildcards and URL userinfo are rejected.
    """
    try:
        host = _canonical_hostname(target)
    except ScopeAuthorizationError:
        return False
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None

    for raw_entry in _configured_targets():
        try:
            normalized, is_network = _canonical_entry(raw_entry)
        except ScopeAuthorizationError:
            continue
        if is_network:
            try:
                if target_ip is not None and target_ip in ipaddress.ip_network(normalized, strict=False):
                    return True
            except ValueError:
                continue
            if target_ip is not None and normalized == str(target_ip):
                return True
            continue
        if normalized.startswith('*.'):
            suffix = normalized[2:]
            if target_ip is None and fnmatch.fnmatchcase(host, f'*.{suffix}') and host != suffix:
                return True
        elif target_ip is None and host == normalized:
            return True
    return False


def require_authorized_target(target: str, *, url: bool = False) -> None:
    if url:
        _canonical_hostname(target, require_http_scheme=True)
    if not is_target_authorized(target):
        raise ScopeAuthorizationError(
            'Target is outside the server-side authorized scan scope. '
            'Configure AUTHORIZED_SCAN_TARGETS before starting a real security run.'
        )
