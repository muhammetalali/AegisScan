from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

from .scope_authorization import require_authorized_target


@dataclass(frozen=True)
class PinnedHTTPResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    resolved_ip: str

    @property
    def content_type(self) -> str:
        return self.headers.get('content-type', '').split(';', 1)[0].strip().lower()

    @property
    def is_redirect(self) -> bool:
        return self.status in {301, 302, 303, 307, 308}


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(str(url).strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
    if scheme not in {'http', 'https'} or not host or parsed.username or parsed.password:
        raise ValueError('HTTP transport requires an absolute HTTP(S) URL without embedded credentials')
    try:
        port = parsed.port or (443 if scheme == 'https' else 80)
    except ValueError as exc:
        raise ValueError('HTTP target contains an invalid port') from exc
    return scheme, host, port


def _scope_url(url: str) -> str:
    parsed = urlsplit(str(url).strip())
    origin(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', '', ''))


def _socket_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address, port: int):
    if address.version == 6:
        return (str(address), port, 0, 0)
    return (str(address), port)


def request_pinned(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int = 10,
    max_body_bytes: int = 262144,
) -> PinnedHTTPResponse:
    """Send one HTTP request to the exact IP addresses approved by scope authorization.

    DNS is resolved and authorized immediately before the connection. The socket is
    then connected directly to that checked IP while preserving the original Host
    header and TLS SNI/certificate validation. Proxy environment variables and a
    second DNS lookup are never consulted.
    """
    verb = str(method).strip().upper()
    if verb not in {'GET', 'HEAD', 'OPTIONS'}:
        raise ValueError(f'Pinned HTTP transport does not permit method: {verb}')
    if not 1 <= int(timeout) <= 30:
        raise ValueError('Pinned HTTP timeout must be between 1 and 30 seconds')
    if not 0 <= int(max_body_bytes) <= 2097152:
        raise ValueError('Pinned HTTP response limit must be between 0 and 2097152 bytes')

    scheme, host, port = origin(url)
    checked = require_authorized_target(_scope_url(url), url=True, resolve_dns=True)
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in checked:
        try:
            addresses.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    if not addresses:
        raise ValueError('HTTP execution requires at least one explicitly resolved authorized destination')

    parsed = urlsplit(url)
    request_path = urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
    request_headers = {
        'User-Agent': 'AegisScan-PinnedHTTP/1.0',
        'Accept': 'application/json, application/yaml, text/yaml, */*;q=0.1',
        **{str(key): str(value) for key, value in (headers or {}).items()},
    }
    last_error: OSError | ssl.SSLError | None = None

    for address in addresses:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        raw_socket = socket.socket(
            socket.AF_INET6 if address.version == 6 else socket.AF_INET,
            socket.SOCK_STREAM,
        )
        transport_socket: socket.socket | ssl.SSLSocket = raw_socket
        try:
            raw_socket.settimeout(timeout)
            raw_socket.connect(_socket_address(address, port))
            if scheme == 'https':
                transport_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=host)
            connection.sock = transport_socket
            connection.request(verb, request_path, headers=request_headers)
            response = connection.getresponse()
            declared = response.getheader('Content-Length')
            if declared:
                try:
                    if int(declared) > max_body_bytes:
                        raise ValueError(f'HTTP response exceeds max_body_bytes={max_body_bytes}')
                except ValueError as exc:
                    if 'exceeds max_body_bytes' in str(exc):
                        raise
            body = response.read(max_body_bytes + 1)
            if len(body) > max_body_bytes:
                raise ValueError(f'HTTP response exceeds max_body_bytes={max_body_bytes}')
            normalized_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                name = str(key).lower()[:100]
                text = str(value)[:4096]
                if name in normalized_headers:
                    normalized_headers[name] = f'{normalized_headers[name]}, {text}'[:4096]
                else:
                    normalized_headers[name] = text
            return PinnedHTTPResponse(
                status=int(response.status),
                headers=normalized_headers,
                body=body,
                url=url,
                resolved_ip=str(address),
            )
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
        finally:
            connection.close()
            try:
                transport_socket.close()
            except OSError:
                pass
            if transport_socket is not raw_socket:
                try:
                    raw_socket.close()
                except OSError:
                    pass

    raise RuntimeError(f'Unable to connect to any authorized destination for {host}') from last_error


def get_pinned_same_origin(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int = 10,
    max_body_bytes: int = 262144,
    max_redirects: int = 0,
) -> PinnedHTTPResponse:
    current = str(url).strip()
    initial_origin = origin(current)
    for redirect_count in range(max_redirects + 1):
        response = request_pinned(
            'GET',
            current,
            headers=headers,
            timeout=timeout,
            max_body_bytes=max_body_bytes,
        )
        if not response.is_redirect:
            return response
        if redirect_count >= max_redirects:
            raise RuntimeError('HTTP redirect limit exceeded')
        location = response.headers.get('location', '').strip()
        if not location:
            raise RuntimeError('HTTP redirect omitted Location header')
        redirected = urljoin(current, location)
        if origin(redirected) != initial_origin:
            raise RuntimeError('HTTP redirect crossed the authorized target origin')
        current = redirected
    raise RuntimeError('HTTP redirect handling reached an invalid state')
