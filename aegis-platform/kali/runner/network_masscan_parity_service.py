#!/usr/bin/env python3
"""Parity-only, loopback-bound governed Kali Masscan candidate.

This provider is deliberately isolated from production dispatch. It accepts only a
bound semantic Masscan intent and fails closed on authorization, scope, target,
option, runtime-manifest, or privilege drift.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

RUNTIME_MANIFEST = Path('/opt/aegis-runner/runtime-manifest.json')
TOOL_MANIFEST = Path('/opt/aegis-runner/tool-manifest.json')
MASSCAN = '/usr/bin/masscan'
MAX_REQUEST_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_LISTEN_HOST = os.environ.get('AEGIS_MASSCAN_PARITY_LISTEN_HOST', '127.0.0.1')
_LISTEN_PORT = int(os.environ.get('AEGIS_MASSCAN_PARITY_LISTEN_PORT', '18767'))
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_REF_RE = re.compile(r'^[A-Za-z0-9:._-]{1,255}$')
_PORT_TOKEN_RE = re.compile(r'^[0-9]{1,5}(?:-[0-9]{1,5})?$')
_NET_RAW_MASK = 1 << 13


class ProtocolError(ValueError):
    pass


def _load_json(raw: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError(f'duplicate JSON field: {key}')
            result[key] = value
        return result

    try:
        payload = json.loads(raw.decode('utf-8'), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError('request body must be valid UTF-8 JSON') from exc
    if not isinstance(payload, dict):
        raise ProtocolError('request body must be a JSON object')
    return payload


def _sha256(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_REQUEST_BYTES:
        raise RuntimeError(f'manifest too large: {path}')
    return _load_json(raw)


def _truthy(name: str) -> bool:
    return os.environ.get(name, '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _bounded_ref(name: str, value: Any) -> str:
    ref = str(value or '').strip()
    if not _REF_RE.fullmatch(ref):
        raise ProtocolError(f'{name} is missing or invalid')
    return ref


def _canonical_target(value: Any) -> str:
    target = str(value or '').strip()
    if not target or len(target) > 64 or any(ch in target for ch in '\r\n\x00'):
        raise ProtocolError('target is missing or invalid')
    try:
        if '/' in target:
            return str(ipaddress.ip_network(target, strict=False))
        return str(ipaddress.ip_address(target))
    except ValueError as exc:
        raise ProtocolError('Masscan parity target must be an IP address or network') from exc


def _canonical_ports(value: Any) -> str:
    raw = str(value or '').strip()
    if not raw or len(raw) > 512 or any(ch.isspace() for ch in raw):
        raise ProtocolError('ports is missing or invalid')
    normalized: list[str] = []
    for token in raw.split(','):
        if not _PORT_TOKEN_RE.fullmatch(token):
            raise ProtocolError('ports must be comma-separated TCP ports or ranges')
        if '-' in token:
            start_text, end_text = token.split('-', 1)
            start, end = int(start_text), int(end_text)
            if start < 1 or end > 65535 or start > end:
                raise ProtocolError('port range is outside 1-65535 or reversed')
            normalized.append(f'{start}-{end}')
        else:
            port = int(token)
            if port < 1 or port > 65535:
                raise ProtocolError('port is outside 1-65535')
            normalized.append(str(port))
    return ','.join(normalized)


def _positive_int(name: str, value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ProtocolError(f'{name} must be an integer')
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f'{name} must be an integer') from exc
    if parsed < minimum or parsed > maximum:
        raise ProtocolError(f'{name} must be between {minimum} and {maximum}')
    return parsed


def _linux_privilege_boundary() -> dict[str, Any]:
    values: dict[str, str] = {}
    try:
        for line in Path('/proc/self/status').read_text(encoding='utf-8').splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                values[key] = value.strip()
    except OSError as exc:
        raise RuntimeError('cannot read Linux process capability state') from exc

    required = ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb', 'NoNewPrivs')
    missing = [name for name in required if name not in values]
    if missing:
        raise RuntimeError(f'missing Linux privilege state fields: {missing}')
    try:
        caps = {
            name: int(values[name], 16)
            for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')
        }
    except ValueError as exc:
        raise RuntimeError('invalid Linux capability state') from exc

    for name in ('CapEff', 'CapPrm', 'CapBnd'):
        if caps[name] != _NET_RAW_MASK:
            raise RuntimeError(f'{name} must contain exactly CAP_NET_RAW during Masscan parity')
    for name in ('CapInh', 'CapAmb'):
        if caps[name] & ~_NET_RAW_MASK:
            raise RuntimeError(f'{name} contains an unexpected capability during Masscan parity')
    if values['NoNewPrivs'] != '1':
        raise RuntimeError('Masscan parity provider requires no_new_privs')

    return {
        'uid': os.geteuid(),
        'effective': f"{caps['CapEff']:016x}",
        'permitted': f"{caps['CapPrm']:016x}",
        'bounding': f"{caps['CapBnd']:016x}",
        'inheritable': f"{caps['CapInh']:016x}",
        'ambient': f"{caps['CapAmb']:016x}",
        'no_new_privs': True,
        'allowed_capabilities': ['CAP_NET_RAW'],
    }


def _auth_token() -> str:
    token = os.environ.get('AEGIS_KALI_MASSCAN_PARITY_AUTH_TOKEN', '').strip()
    if not _TOKEN_RE.fullmatch(token):
        raise RuntimeError('AEGIS_KALI_MASSCAN_PARITY_AUTH_TOKEN must be 64 lowercase hex characters')
    return token


def _expected_binding() -> dict[str, Any]:
    authorization_ref = _bounded_ref(
        'AEGIS_KALI_MASSCAN_EXPECTED_AUTHORIZATION_REF',
        os.environ.get('AEGIS_KALI_MASSCAN_EXPECTED_AUTHORIZATION_REF'),
    )
    scope_ref = _bounded_ref(
        'AEGIS_KALI_MASSCAN_EXPECTED_SCOPE_REF',
        os.environ.get('AEGIS_KALI_MASSCAN_EXPECTED_SCOPE_REF'),
    )
    target = _canonical_target(os.environ.get('AEGIS_KALI_MASSCAN_EXPECTED_TARGET'))
    ports = _canonical_ports(os.environ.get('AEGIS_KALI_MASSCAN_EXPECTED_PORTS'))
    rate = _positive_int(
        'AEGIS_KALI_MASSCAN_EXPECTED_RATE',
        os.environ.get('AEGIS_KALI_MASSCAN_EXPECTED_RATE'),
        minimum=1,
        maximum=100000,
    )
    return {
        'authorization_ref': authorization_ref,
        'scope_ref': scope_ref,
        'target': target,
        'ports': ports,
        'rate': rate,
    }


def _runtime_contract() -> dict[str, Any]:
    if not _truthy('AEGIS_KALI_MASSCAN_PARITY_MODE'):
        raise RuntimeError('network Masscan candidate is parity-only and requires AEGIS_KALI_MASSCAN_PARITY_MODE=true')
    _auth_token()
    _expected_binding()
    runtime = dict(_manifest(RUNTIME_MANIFEST))
    runtime['_linux_privilege'] = _linux_privilege_boundary()
    if runtime.get('runtime') != 'aegis-kali' or runtime.get('profile') != 'network':
        raise RuntimeError('Masscan parity provider requires the aegis-kali network profile')
    if runtime.get('dispatch_enabled') is not False or runtime.get('dispatch_state') != 'accepted-no-dispatch':
        raise RuntimeError('network profile unexpectedly became production-dispatchable during Masscan parity')
    if runtime.get('tool_manifest_digest') != _sha256(TOOL_MANIFEST):
        raise RuntimeError('runtime/tool manifest digest mismatch')
    capabilities = runtime.get('profile_capabilities')
    tools = runtime.get('profile_tools')
    if not isinstance(capabilities, list) or 'network.masscan' not in capabilities:
        raise RuntimeError('network.masscan is absent from runtime capability placement')
    if not isinstance(tools, dict) or 'masscan' not in tools:
        raise RuntimeError('Masscan tool provenance is absent from runtime manifest')
    if not Path(MASSCAN).is_file() or not os.access(MASSCAN, os.X_OK):
        raise RuntimeError('pinned Masscan binary is unavailable')
    return runtime


def _validate_request(payload: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        'schema_version', 'execution_ref', 'authorization_ref', 'scope_ref',
        'capability_id', 'target', 'options', 'timeout_seconds',
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ProtocolError(f'unsupported request fields: {unknown}')
    if payload.get('schema_version') != 1:
        raise ProtocolError('unsupported request schema_version')
    if payload.get('capability_id') != 'network.masscan':
        raise ProtocolError('parity provider accepts only network.masscan')
    if 'network.masscan' not in runtime['profile_capabilities']:
        raise ProtocolError('network.masscan is not allowed by the runtime manifest')

    execution_ref = _bounded_ref('execution_ref', payload.get('execution_ref'))
    authorization_ref = _bounded_ref('authorization_ref', payload.get('authorization_ref'))
    scope_ref = _bounded_ref('scope_ref', payload.get('scope_ref'))
    target = _canonical_target(payload.get('target'))

    options = payload.get('options')
    if not isinstance(options, dict):
        raise ProtocolError('options must be a JSON object')
    unknown_options = sorted(set(options) - {'ports', 'rate'})
    if unknown_options:
        raise ProtocolError(f'unsupported Masscan options: {unknown_options}')
    ports = _canonical_ports(options.get('ports'))
    rate = _positive_int('rate', options.get('rate'), minimum=1, maximum=100000)
    timeout = _positive_int('timeout_seconds', payload.get('timeout_seconds'), minimum=5, maximum=300)

    expected = _expected_binding()
    if authorization_ref != expected['authorization_ref']:
        raise ProtocolError('authorization_ref does not match the bound parity authorization')
    if scope_ref != expected['scope_ref']:
        raise ProtocolError('scope_ref does not match the bound parity scope')
    if target != expected['target']:
        raise ProtocolError('target does not match the bound parity target')
    if ports != expected['ports']:
        raise ProtocolError('ports do not match the bound parity intent')
    if rate != expected['rate']:
        raise ProtocolError('rate does not match the bound parity intent')

    return {
        'execution_ref': execution_ref,
        'authorization_ref': authorization_ref,
        'scope_ref': scope_ref,
        'capability_id': 'network.masscan',
        'target': target,
        'ports': ports,
        'rate': rate,
        'timeout_seconds': timeout,
    }


def _sanitized_env() -> dict[str, str]:
    return {
        'HOME': '/tmp/aegis-home',
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'NO_COLOR': '1',
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'TMPDIR': '/tmp',
    }


def _execute(request: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    os.makedirs('/tmp/aegis-home', mode=0o700, exist_ok=True)
    command = [
        MASSCAN,
        request['target'],
        '-p', request['ports'],
        '--rate', str(request['rate']),
        '--output-format', 'json',
        '--output-filename', '-',
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_sanitized_env(),
            cwd='/tmp',
            timeout=request['timeout_seconds'],
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError('Masscan parity execution timed out') from exc
    if len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise RuntimeError('Masscan parity output exceeded the 8 MiB limit')
    tool = runtime['profile_tools']['masscan']
    return {
        'schema_version': 1,
        'status': 'completed',
        'execution_ref': request['execution_ref'],
        'authorization_ref': request['authorization_ref'],
        'scope_ref': request['scope_ref'],
        'capability_id': request['capability_id'],
        'target': request['target'],
        'options': {'ports': request['ports'], 'rate': request['rate']},
        'tool': 'masscan',
        'exit_code': int(completed.returncode),
        'stdout': completed.stdout.decode('utf-8', errors='replace'),
        'stderr': completed.stderr.decode('utf-8', errors='replace'),
        'duration_ms': int((time.monotonic() - started) * 1000),
        'runtime': {
            'provider': 'aegis-kali-network-masscan-parity',
            'profile': 'network',
            'runner_version': runtime.get('runner_version'),
            'base_image_digest': runtime.get('base_image_digest'),
            'build_commit': runtime.get('build_commit'),
            'tool_manifest_digest': runtime.get('tool_manifest_digest'),
            'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
            'tool': 'masscan',
            'tool_version': tool.get('version'),
            'tool_source': tool.get('source'),
            'dispatch_state': runtime.get('dispatch_state'),
            'linux_privilege': runtime['_linux_privilege'],
            'binding': {
                'authorization_ref': request['authorization_ref'],
                'scope_ref': request['scope_ref'],
                'target': request['target'],
                'ports': request['ports'],
                'rate': request['rate'],
            },
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisMasscanParity/1'

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        return hmac.compare_digest(
            self.headers.get('X-Aegis-Masscan-Parity-Token', ''),
            _auth_token(),
        )

    def _body(self) -> dict[str, Any]:
        raw = self.headers.get('Content-Length')
        if raw is None:
            raise ProtocolError('Content-Length is required')
        try:
            length = int(raw)
        except ValueError as exc:
            raise ProtocolError('Content-Length must be an integer') from exc
        if length < 2 or length > MAX_REQUEST_BYTES:
            raise ProtocolError('request body exceeds the provider limit')
        if self.headers.get_content_type() != 'application/json':
            raise ProtocolError('Content-Type must be application/json')
        return _load_json(self.rfile.read(length))

    def do_GET(self) -> None:
        if self.path == '/healthz':
            try:
                runtime = _runtime_contract()
                self._json(HTTPStatus.OK, {
                    'status': 'ok',
                    'profile': runtime['profile'],
                    'capability_id': 'network.masscan',
                    'parity_only': True,
                })
            except Exception as exc:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {'status': 'unhealthy', 'error': str(exc)})
            return
        if self.path == '/v1/runtime':
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {'status': 'unauthorized'})
                return
            try:
                runtime = _runtime_contract()
                self._json(HTTPStatus.OK, {
                    'status': 'ok',
                    'runtime': {
                        'provider': 'aegis-kali-network-masscan-parity',
                        'profile': 'network',
                        'runner_version': runtime.get('runner_version'),
                        'build_commit': runtime.get('build_commit'),
                        'base_image_digest': runtime.get('base_image_digest'),
                        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                        'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                        'dispatch_state': runtime.get('dispatch_state'),
                        'linux_privilege': runtime['_linux_privilege'],
                        'binding': _expected_binding(),
                    },
                })
            except Exception as exc:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {'status': 'unhealthy', 'error': str(exc)})
            return
        self._json(HTTPStatus.NOT_FOUND, {'status': 'not_found'})

    def do_POST(self) -> None:
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {'status': 'unauthorized'})
            return
        try:
            if self.path != '/v1/execute':
                self._json(HTTPStatus.NOT_FOUND, {'status': 'not_found'})
                return
            runtime = _runtime_contract()
            request = _validate_request(self._body(), runtime)
            self._json(HTTPStatus.OK, _execute(request, runtime))
        except ProtocolError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {'status': 'rejected', 'error': str(exc)})
        except TimeoutError as exc:
            self._json(HTTPStatus.GATEWAY_TIMEOUT, {'status': 'failed', 'error': str(exc)})
        except Exception as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {'status': 'failed', 'error': str(exc)})


def main() -> int:
    if _LISTEN_HOST != '127.0.0.1':
        raise SystemExit('Masscan parity provider must bind to 127.0.0.1')
    if _LISTEN_PORT < 1024 or _LISTEN_PORT > 65535:
        raise SystemExit('AEGIS_MASSCAN_PARITY_LISTEN_PORT must be between 1024 and 65535')
    _runtime_contract()
    server = ThreadingHTTPServer((_LISTEN_HOST, _LISTEN_PORT), Handler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
