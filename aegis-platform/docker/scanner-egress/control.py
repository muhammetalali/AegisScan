#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TABLE = 'aegis_egress'
SET4 = 'dynamic_ipv4'
SET6 = 'dynamic_ipv6'
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


def _run_nft(statement: str) -> None:
    proc = subprocess.run(
        ['nft', '-f', '-'],
        input=statement,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )
    if proc.returncode != 0 and 'File exists' not in proc.stderr:
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
        if self.path != '/v1/allow':
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
            normalized, set_name = _normalize_target(payload.get('target'))
            _run_nft(f'add element netdev {TABLE} {set_name} {{ {normalized} }}\n')
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
            self._json(422, {'status': 'rejected', 'detail': str(exc)})
            return
        self._json(200, {'status': 'ok', 'target': normalized})


def main() -> None:
    if not TOKEN:
        raise SystemExit('AEGIS_SCANNER_EGRESS_CONTROL_TOKEN is required')
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == '__main__':
    main()
