from __future__ import annotations

import fnmatch
import ipaddress
import os
from urllib.parse import urlparse


class ScopeAuthorizationError(ValueError):
    """Raised when a target is not explicitly authorized for security execution."""


def _configured_targets() -> list[str]:
    raw = os.getenv('AUTHORIZED_SCAN_TARGETS', '')
    return [item.strip() for item in raw.split(',') if item.strip()]


def _hostname(value: str) -> str:
    candidate = value.strip()
    parsed = urlparse(candidate if '://' in candidate else f'//{candidate}', scheme='http')
    return (parsed.hostname or candidate.split('/')[0].split(':')[0]).strip('.').lower()


def is_target_authorized(target: str) -> bool:
    """Match a target against the explicit server-side authorization allow-list.

    Supported entries: exact IPs, CIDRs, exact hostnames, wildcard hostnames and
    domain suffixes. An empty allow-list denies execution by default.
    """
    entries = _configured_targets()
    if not entries:
        return False

    host = _hostname(target)
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None

    for entry in entries:
        normalized = entry.strip().lower().strip('.')
        try:
            if target_ip is not None:
                if '/' in normalized:
                    if target_ip in ipaddress.ip_network(normalized, strict=False):
                        return True
                elif target_ip == ipaddress.ip_address(normalized):
                    return True
                continue
        except ValueError:
            pass

        if fnmatch.fnmatch(host, normalized):
            return True
        if host == normalized or host.endswith('.' + normalized):
            return True

    return False


def require_authorized_target(target: str) -> None:
    if not is_target_authorized(target):
        raise ScopeAuthorizationError(
            'Target is outside the server-side authorized scan scope. '
            'Configure AUTHORIZED_SCAN_TARGETS before starting a real security run.'
        )
