#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TABLE = 'aegis_egress'
SET4 = 'dynamic_ipv4'
SET6 = 'dynamic_ipv6'
LEASE4 = 'leased_ipv4'
LEASE6 = 'leased_ipv6'
LEASE_MIN_SECONDS = 15
LEASE_MAX_SECONDS = 900
LEASE_CAPACITY = 32
LEASE_RECORD_CAPACITY = 256
_LEASE_LOCK = threading.RLock()
_LEASES: dict[str, dict] = {}
_LEASE_TARGETS: dict[str, str] = {}
_PRIVATE_V4 = tuple(ipaddress.ip_network(value) for value in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'
))
_PRIVATE_V6 = (ipaddress.ip_network('fc00::/7'),)
ROOT = os.getenv('AEGIS_SCANNER_EGRESS_CONTROL_ROOT', '').strip()
TOKEN = (
    hmac.new(
        ROOT.encode('utf-8'),
        b'aegisscan-scanner-egress-control-v1',
        hashlib.sha256,
    ).hexdigest()
    if ROOT else ''
)
HOST = '127.0.0.1'
PORT = 18780


def _run_nft(statement: str, *, ignore_exists: bool = True) -> None:
    proc = subprocess.run(
        ['nft', '-f', '-'],
        input=statement,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )
    if proc.returncode != 0 and not (ignore_exists and 'File exists' in proc.stderr):
        raise RuntimeError(proc.stderr.strip() or 'nft update failed')


def _normalize_target(value: object) -> tuple[str, str]:
    raw = str(value or '').strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        if address.is_multicast or address.is_unspecified:
            raise ValueError('multicast and unspecified targets are not supported')
        return str(address), SET4 if address.version == 4 else SET6
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ValueError('target must be an IP address or CIDR') from exc
    if network.network_address.is_multicast or network.network_address.is_unspecified:
        raise ValueError('multicast and unspecified targets are not supported')
    return str(network), SET4 if network.version == 4 else SET6


def _private_exact_address(value: object) -> tuple[str, str]:
    """Leases never authorize CIDRs, globally routed addresses or local endpoints."""
    if not isinstance(value, str) or not value or '/' in value:
        raise ValueError('temporary egress lease requires one exact private IP')
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError('temporary egress lease requires one exact private IP') from exc
    boundaries = _PRIVATE_V4 if address.version == 4 else _PRIVATE_V6
    if not any(address in boundary for boundary in boundaries):
        raise ValueError('temporary egress lease must be RFC1918, CGNAT or IPv6 ULA')
    return str(address), LEASE4 if address.version == 4 else LEASE6


def _expire_local_leases(now: float) -> None:
    """Kernel nft timeouts are authoritative; forget expired ownership only."""
    for lease_id, lease in list(_LEASES.items()):
        if lease['active'] and lease['deadline'] <= now:
            lease['active'] = False
            if _LEASE_TARGETS.get(lease['target']) == lease_id:
                _LEASE_TARGETS.pop(lease['target'], None)
        if not lease['active'] and lease['deadline'] + 3600 < now:
            _LEASES.pop(lease_id, None)


def _create_lease(payload: dict) -> dict:
    if set(payload) != {'target', 'ttl_seconds'}:
        raise ValueError('lease requires only target and ttl_seconds')
    ttl = payload['ttl_seconds']
    if type(ttl) is not int or not LEASE_MIN_SECONDS <= ttl <= LEASE_MAX_SECONDS:
        raise ValueError('lease duration is outside the bounded 15..900s window')
    target, set_name = _private_exact_address(payload['target'])
    with _LEASE_LOCK:
        now = time.monotonic()
        _expire_local_leases(now)
        if target in _LEASE_TARGETS:
            raise ValueError('target already has an active lease')
        if len(_LEASE_TARGETS) >= LEASE_CAPACITY or len(_LEASES) >= LEASE_RECORD_CAPACITY:
            raise ValueError('temporary egress lease capacity exceeded')
        # Kernel timeout survives controller process crashes; never add a
        # persistent element to an unbounded dynamic authorization set.
        _run_nft(
            f'add element netdev {TABLE} {set_name} {{ {target} timeout {ttl}s }}\n',
            ignore_exists=False,
        )
        lease_id = secrets.token_urlsafe(32)
        _LEASES[lease_id] = {
            'target': target, 'set_name': set_name,
            'deadline': now + ttl, 'active': True,
        }
        _LEASE_TARGETS[target] = lease_id
    return {'status': 'leased', 'target': target, 'ttl_seconds': ttl, 'lease_id': lease_id}


def _revoke_lease(payload: dict) -> dict:
    if set(payload) != {'lease_id'}:
        raise ValueError('revoke requires only the lease_id')
    lease_id = payload.get('lease_id')
    if not isinstance(lease_id, str) or len(lease_id) < 32 or len(lease_id) > 128:
        raise ValueError('invalid temporary lease reference')
    with _LEASE_LOCK:
        _expire_local_leases(time.monotonic())
        lease = _LEASES.get(lease_id)
        if lease is None:
            raise ValueError('unknown temporary lease reference')
        if not lease['active']:
            return {'status': 'already_inactive'}
        target = lease['target']
        if _LEASE_TARGETS.get(target) != lease_id:
            raise RuntimeError('temporary lease ownership mismatch')
        # Target-specific removal does not remove static/global authorization
        # or the distinct permanent dynamic sets used by other scans.
        try:
            _run_nft(
                f"delete element netdev {TABLE} {lease['set_name']} {{ {target} }}\n",
                ignore_exists=False,
            )
        except RuntimeError as exc:
            if 'No such file or directory' not in str(exc):
                raise
            # An expired element is safe, but a missing nft table/set is NOT.
            # Require the fail-closed kernel policy and isolated lease set to
            # still exist before treating the expired element as revoked.
            _run_nft(
                f"list set netdev {TABLE} {lease['set_name']}\n",
                ignore_exists=False,
            )
        lease['active'] = False
        _LEASE_TARGETS.pop(target, None)
    return {'status': 'revoked', 'target': target}


class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisEgress/1.0'
    sys_version = ''

    def log_message(self, format: str, *args) -> None:
        return

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != '/healthz':
            self._json(404, {'status': 'not_found'})
            return
        self._json(200, {'status': 'ok', 'service': 'scanner-egress-control'})

    def do_POST(self) -> None:
        if self.path not in {'/v1/allow', '/v1/lease', '/v1/revoke'}:
            self._json(404, {'status': 'not_found'})
            return
        supplied = self.headers.get('X-Aegis-Egress-Token', '')
        if not TOKEN or not hmac.compare_digest(supplied, TOKEN):
            self._json(403, {'status': 'denied'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 2 or length > 4096:
                raise ValueError('invalid request size')
            payload = json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(payload, dict):
                raise ValueError('request must be a JSON object')
            if self.path == '/v1/lease':
                outcome = _create_lease(payload)
            elif self.path == '/v1/revoke':
                outcome = _revoke_lease(payload)
            else:
                normalized, set_name = _normalize_target(payload.get('target'))
                _run_nft(f'add element netdev {TABLE} {set_name} {{ {normalized} }}\n')
                outcome = {'status': 'ok', 'target': normalized}
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
            self._json(422, {'status': 'rejected', 'detail': str(exc)})
            return
        self._json(200, outcome)


def main() -> None:
    if not TOKEN:
        raise SystemExit('AEGIS_SCANNER_EGRESS_CONTROL_ROOT is required')
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == '__main__':
    main()
