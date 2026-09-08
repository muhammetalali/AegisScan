from __future__ import annotations

import ipaddress
import os
import re
import socket
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

    # Literal IPs are canonicalized before URL parsing so bare IPv6 is treated
    # as an IP address rather than a malformed host:port expression.
    if '://' not in candidate and not candidate.startswith('['):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass

    try:
        parsed = urlsplit(candidate if '://' in candidate else f'//{candidate}')
        if parsed.scheme and parsed.scheme.lower() not in {'http', 'https'}:
            raise ScopeAuthorizationError('Unsupported target scheme')
        if require_http_scheme and parsed.scheme.lower() not in {'http', 'https'}:
            raise ScopeAuthorizationError('URL scan targets require http or https')
        if parsed.username is not None or parsed.password is not None:
            raise ScopeAuthorizationError('Target userinfo is not allowed')
        if parsed.fragment or parsed.query:
            raise ScopeAuthorizationError('Target fragments and query strings are not allowed')
        if parsed.path not in {'', '/'} and parsed.scheme == '':
            raise ScopeAuthorizationError('Host targets cannot contain a path')
        host = parsed.hostname
    except ValueError as exc:
        raise ScopeAuthorizationError('Target host syntax is invalid') from exc
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


def _canonical_entry(entry: str) -> tuple[str, bool, bool]:
    value = entry.strip()
    if not value or _CONTROL_RE.search(value):
        raise ScopeAuthorizationError('Configured authorization contains invalid characters')
    if value in {'*', '**', '*.*'} or value.startswith('?.'):
        raise ScopeAuthorizationError('Global wildcard authorization is forbidden')
    try:
        return str(ipaddress.ip_network(value, strict=False)), True, False
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_address(value)), True, False
    except ValueError:
        pass
    wildcard = '*' in value or '?' in value
    normalized = value.lower().strip('.')
    if wildcard:
        if not normalized.startswith('*.') or normalized.count('*') != 1 or '?' in normalized:
            raise ScopeAuthorizationError('Only a single left-most wildcard label is supported')
        normalized = normalized[2:]
    try:
        normalized = normalized.encode('idna').decode('ascii').lower().strip('.')
    except UnicodeError as exc:
        raise ScopeAuthorizationError('Configured hostname is not valid IDNA') from exc
    if not normalized:
        raise ScopeAuthorizationError('Configured hostname is empty')
    return normalized, False, wildcard


def _target_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    candidate = str(value).strip()
    if '://' in candidate or '/' not in candidate:
        return None
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None


def _configured_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw_entry in _configured_targets():
        try:
            normalized, is_network, _ = _canonical_entry(raw_entry)
        except ScopeAuthorizationError:
            continue
        if not is_network:
            continue
        try:
            networks.append(ipaddress.ip_network(normalized, strict=False))
        except ValueError:
            continue
    return networks


def _ip_explicitly_authorized(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        address.version == network.version and address in network
        for network in _configured_networks()
    )


def _resolve_host_addresses(host: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ScopeAuthorizationError(f'Target DNS resolution failed: {host}') from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for answer in answers:
        sockaddr = answer[4]
        if not sockaddr:
            continue
        raw_address = str(sockaddr[0]).split('%', 1)[0]
        try:
            addresses.add(ipaddress.ip_address(raw_address))
        except ValueError:
            continue
    if not addresses:
        raise ScopeAuthorizationError(f'Target DNS resolution returned no IP addresses: {host}')
    return tuple(sorted(addresses, key=lambda item: (item.version, int(item))))


def _enforce_resolved_egress(host: str) -> tuple[str, ...]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    # Literal IPs are an explicit operator decision in the server-side
    # allow-list. There is no DNS indirection to exploit.
    if address is not None:
        return (str(address),)

    # Single-label service identities are used by isolated Docker/Kubernetes
    # test targets. They must still be explicitly allow-listed. Localhost is
    # never accepted by hostname alias; authorize a loopback IP explicitly if
    # a deliberately isolated test requires it.
    if '.' not in host:
        if host in {'localhost', 'localhost.localdomain'}:
            raise ScopeAuthorizationError('Localhost aliases require explicit IP/CIDR authorization')
        return ()

    resolved = _resolve_host_addresses(host)
    for destination in resolved:
        if destination.is_global:
            continue
        if _ip_explicitly_authorized(destination):
            continue
        raise ScopeAuthorizationError(
            'Target hostname resolves to a non-global destination that is not '
            f'explicitly authorized by IP/CIDR: {destination}'
        )
    return tuple(str(item) for item in resolved)


def is_target_authorized(target: str, *, resolve_dns: bool = False) -> bool:
    """Match a target against the explicit server-side authorization allow-list.

    With ``resolve_dns=True`` every non-global address reached through a FQDN
    must also be explicitly authorized by IP/CIDR. This prevents an allowed
    hostname from becoming loopback, link-local/cloud-metadata, private,
    reserved, multicast, or another non-global destination through DNS.
    """
    network_target = _target_network(target)
    if network_target is not None:
        for raw_entry in _configured_targets():
            try:
                normalized, is_network, _ = _canonical_entry(raw_entry)
            except ScopeAuthorizationError:
                continue
            if not is_network:
                continue
            configured_network = ipaddress.ip_network(normalized, strict=False)
            if (
                configured_network.version == network_target.version
                and network_target.subnet_of(configured_network)
            ):
                return True
        return False

    try:
        host = _canonical_hostname(target)
    except ScopeAuthorizationError:
        return False
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None

    matched = False
    for raw_entry in _configured_targets():
        try:
            normalized, is_network, wildcard = _canonical_entry(raw_entry)
        except ScopeAuthorizationError:
            continue
        if is_network:
            if target_ip is not None and target_ip in ipaddress.ip_network(normalized, strict=False):
                matched = True
                break
            continue
        if target_ip is not None:
            continue
        if wildcard and host.endswith('.' + normalized):
            matched = True
            break
        if not wildcard and host == normalized:
            matched = True
            break

    if not matched:
        return False
    if not resolve_dns:
        return True
    try:
        _enforce_resolved_egress(host)
    except ScopeAuthorizationError:
        return False
    return True


def require_authorized_target(
    target: str,
    *,
    url: bool = False,
    resolve_dns: bool = False,
) -> tuple[str, ...]:
    host = _canonical_hostname(target, require_http_scheme=url)
    if not is_target_authorized(target):
        raise ScopeAuthorizationError(
            'Target is outside the server-side authorized scan scope. '
            'Configure AUTHORIZED_SCAN_TARGETS before starting a real security run.'
        )
    if not resolve_dns:
        return ()
    return _enforce_resolved_egress(host)
