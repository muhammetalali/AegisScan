#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MASSCAN = '/usr/bin/masscan'
RUNTIME_MANIFEST = Path('/opt/aegis-runner/runtime-manifest.json')
MAX_REQUEST_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
_NET_RAW_MASK = 1 << 13
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_REF_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9:._/@+-]{0,254}$')
_IFACE_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
_MAC_RE = re.compile(r'^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')
_PORT_TOKEN_RE = re.compile(r'^\d{1,5}(?:-\d{1,5})?$')
_LISTEN_HOST = os.getenv('AEGIS_MASSCAN_LISTEN_HOST', '127.0.0.1').strip()
_LISTEN_PORT = int(os.getenv('AEGIS_MASSCAN_LISTEN_PORT', '18767'))
_ACTIVE_LIMIT = threading.BoundedSemaphore(2)
_ACTIVE_LOCK = threading.Lock()
_ACTIVE: dict[str, 'ActiveExecution'] = {}


class ProtocolError(RuntimeError):
    pass


class ExecutionCancelled(RuntimeError):
    pass


class OutputLimitExceeded(RuntimeError):
    pass


@dataclass
class ActiveExecution:
    token: str
    process: subprocess.Popen[bytes]
    state: str = 'running'
    lock: threading.Lock = field(default_factory=threading.Lock)


def _sha256(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_runtime() -> dict[str, Any]:
    try:
        runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError('cannot load network Masscan runtime manifest') from exc
    if not isinstance(runtime, dict):
        raise RuntimeError('network Masscan runtime manifest must be an object')
    return runtime


def _linux_privilege_boundary() -> dict[str, Any]:
    values: dict[str, str] = {}
    for line in Path('/proc/self/status').read_text(encoding='utf-8').splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            values[key] = value.strip()
    for key in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb', 'NoNewPrivs'):
        if key not in values:
            raise RuntimeError(f'missing Linux privilege state field {key}')
    caps = {name: int(values[name], 16) for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')}
    for name in ('CapEff', 'CapPrm', 'CapBnd'):
        if caps[name] != _NET_RAW_MASK:
            raise RuntimeError(f'{name} must contain exactly CAP_NET_RAW')
    for name in ('CapInh', 'CapAmb'):
        if caps[name] & ~_NET_RAW_MASK:
            raise RuntimeError(f'{name} contains an unexpected capability')
    if values['NoNewPrivs'] != '1':
        raise RuntimeError('Masscan provider requires no_new_privs')
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


def _runtime_contract() -> dict[str, Any]:
    runtime = _load_runtime()
    if runtime.get('profile') != 'network':
        raise RuntimeError('Masscan provider requires the network profile')
    if runtime.get('dispatch_enabled') is not True:
        raise RuntimeError('Masscan production dispatch is not enabled')
    if runtime.get('dispatch_state') != 'semantic-masscan-provider':
        raise RuntimeError('Masscan dispatch state mismatch')
    if runtime.get('dispatch_capabilities') != ['network.masscan']:
        raise RuntimeError('Masscan provider must dispatch only network.masscan')
    tools = runtime.get('profile_tools')
    if not isinstance(tools, dict) or not isinstance(tools.get('masscan'), dict):
        raise RuntimeError('Masscan tool provenance is missing')
    if tools['masscan'].get('version') != '2:1.3.2+ds1-2':
        raise RuntimeError('Masscan tool version mismatch')
    runtime = dict(runtime)
    runtime['_linux_privilege'] = _linux_privilege_boundary()
    return runtime


def _provider_auth_token() -> str:
    token = os.getenv('AEGIS_KALI_MASSCAN_AUTH_TOKEN', '').strip()
    if not _TOKEN_RE.fullmatch(token):
        raise RuntimeError('AEGIS_KALI_MASSCAN_AUTH_TOKEN must be 64 lowercase hex characters')
    return token


def _bounded_ref(name: str, value: Any) -> str:
    text = str(value or '').strip()
    if not _REF_RE.fullmatch(text):
        raise ProtocolError(f'{name} is missing or invalid')
    return text


def _canonical_target(value: Any) -> str:
    raw = str(value or '').strip()
    try:
        if '/' in raw:
            network = ipaddress.ip_network(raw, strict=False)
            if network.version != 4:
                raise ValueError
            return str(network)
        address = ipaddress.ip_address(raw)
        if address.version != 4:
            raise ValueError
        return str(address)
    except ValueError as exc:
        raise ProtocolError('target must be an IPv4 address or network') from exc


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


def _optional_interface(value: Any) -> str | None:
    if value in {None, ''}:
        return None
    text = str(value).strip()
    if not _IFACE_RE.fullmatch(text):
        raise ProtocolError('interface is invalid')
    return text


def _optional_ipv4(value: Any) -> str | None:
    if value in {None, ''}:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ProtocolError('adapter_ip is invalid') from exc
    if address.version != 4:
        raise ProtocolError('adapter_ip must be IPv4')
    return str(address)


def _optional_mac(name: str, value: Any) -> str | None:
    if value in {None, ''}:
        return None
    text = str(value).strip()
    if not _MAC_RE.fullmatch(text):
        raise ProtocolError(f'{name} is invalid')
    return text.replace('-', ':').lower()


def _validate_request(payload: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        'schema_version', 'execution_ref', 'authorization_ref', 'scope_ref',
        'control_token', 'capability_id', 'target', 'options', 'timeout_seconds',
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ProtocolError(f'unsupported request fields: {unknown}')
    if payload.get('schema_version') != 1:
        raise ProtocolError('unsupported request schema_version')
    if payload.get('capability_id') != 'network.masscan':
        raise ProtocolError('provider accepts only network.masscan')
    execution_ref = _bounded_ref('execution_ref', payload.get('execution_ref'))
    authorization_ref = _bounded_ref('authorization_ref', payload.get('authorization_ref'))
    scope_ref = _bounded_ref('scope_ref', payload.get('scope_ref'))
    control_token = str(payload.get('control_token') or '')
    if not _TOKEN_RE.fullmatch(control_token):
        raise ProtocolError('control_token is missing or invalid')
    target = _canonical_target(payload.get('target'))
    options = payload.get('options')
    if not isinstance(options, dict):
        raise ProtocolError('options must be a JSON object')
    allowed_options = {'ports', 'rate', 'interface', 'adapter_ip', 'adapter_mac', 'router_mac'}
    unknown_options = sorted(set(options) - allowed_options)
    if unknown_options:
        raise ProtocolError(f'unsupported Masscan options: {unknown_options}')
    return {
        'execution_ref': execution_ref,
        'authorization_ref': authorization_ref,
        'scope_ref': scope_ref,
        'control_token': control_token,
        'capability_id': 'network.masscan',
        'target': target,
        'ports': _canonical_ports(options.get('ports')),
        'rate': _positive_int('rate', options.get('rate'), minimum=1, maximum=100000),
        'interface': _optional_interface(options.get('interface')),
        'adapter_ip': _optional_ipv4(options.get('adapter_ip')),
        'adapter_mac': _optional_mac('adapter_mac', options.get('adapter_mac')),
        'router_mac': _optional_mac('router_mac', options.get('router_mac')),
        'timeout_seconds': _positive_int('timeout_seconds', payload.get('timeout_seconds'), minimum=5, maximum=300),
    }


def _sanitized_env() -> dict[str, str]:
    return {
        'HOME': '/tmp/aegis-home', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'NO_COLOR': '1', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'TMPDIR': '/tmp',
    }


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def _register_execution(execution_ref: str, record: ActiveExecution) -> None:
    with _ACTIVE_LOCK:
        if execution_ref in _ACTIVE:
            raise ProtocolError('execution_ref is already active')
        _ACTIVE[execution_ref] = record


def _remove_execution(execution_ref: str, record: ActiveExecution) -> None:
    with _ACTIVE_LOCK:
        if _ACTIVE.get(execution_ref) is record:
            _ACTIVE.pop(execution_ref, None)


def _control_execution(execution_ref: str, token: str, state: str) -> str:
    if state not in {'running', 'paused', 'cancelled'}:
        raise ProtocolError('control state must be running, paused, or cancelled')
    with _ACTIVE_LOCK:
        record = _ACTIVE.get(execution_ref)
    if record is None:
        raise ProtocolError('execution_ref is not active')
    if token != record.token:
        raise ProtocolError('control token does not match the active execution')
    with record.lock:
        if record.state == 'cancelled':
            return record.state
        if state == 'paused' and record.state != 'paused' and record.process.poll() is None:
            os.killpg(record.process.pid, signal.SIGSTOP)
            record.state = 'paused'
        elif state == 'running' and record.state == 'paused' and record.process.poll() is None:
            os.killpg(record.process.pid, signal.SIGCONT)
            record.state = 'running'
        elif state == 'cancelled':
            record.state = 'cancelled'
            _terminate_process_group(record.process)
        return record.state


def _stream_reader(stream, chunks: list[bytes], overflow: threading.Event) -> None:
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        total += len(chunk)
        if total > MAX_OUTPUT_BYTES:
            overflow.set()
            return
        chunks.append(chunk)


def _execute(request: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    os.makedirs('/tmp/aegis-home', mode=0o700, exist_ok=True)
    command = [MASSCAN, request['target'], '-p', request['ports'], '--rate', str(request['rate'])]
    optional_flags = (
        ('--adapter', request['interface']),
        ('--adapter-ip', request['adapter_ip']),
        ('--adapter-mac', request['adapter_mac']),
        ('--router-mac', request['router_mac']),
    )
    for flag, value in optional_flags:
        if value is not None:
            command.extend([flag, value])
    command.extend(['--output-format', 'json', '--output-filename', '-'])

    acquired = _ACTIVE_LIMIT.acquire(timeout=5)
    if not acquired:
        raise RuntimeError('Masscan provider concurrency limit reached')
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    record: ActiveExecution | None = None
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, start_new_session=True, env=_sanitized_env(), cwd='/tmp',
        )
        assert process.stdout is not None and process.stderr is not None
        record = ActiveExecution(request['control_token'], process)
        _register_execution(request['execution_ref'], record)
        readers = [
            threading.Thread(target=_stream_reader, args=(process.stdout, stdout_chunks, overflow), daemon=True),
            threading.Thread(target=_stream_reader, args=(process.stderr, stderr_chunks, overflow), daemon=True),
        ]
        for thread in readers:
            thread.start()
        deadline = started + request['timeout_seconds']
        while process.poll() is None:
            if overflow.is_set():
                _terminate_process_group(process)
                raise OutputLimitExceeded('Masscan provider output exceeded the 8 MiB stream limit')
            if time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise TimeoutError('Masscan provider execution timed out')
            with record.lock:
                cancelled = record.state == 'cancelled'
                paused = record.state == 'paused'
            if cancelled:
                raise ExecutionCancelled('Masscan provider execution cancelled')
            time.sleep(0.05)
            if paused:
                deadline += 0.05
        for thread in readers:
            thread.join(timeout=2)
        with record.lock:
            if record.state == 'cancelled':
                raise ExecutionCancelled('Masscan provider execution cancelled')
        if overflow.is_set():
            raise OutputLimitExceeded('Masscan provider output exceeded the 8 MiB stream limit')
        options = {
            'ports': request['ports'], 'rate': request['rate'],
            'interface': request['interface'], 'adapter_ip': request['adapter_ip'],
            'adapter_mac': request['adapter_mac'], 'router_mac': request['router_mac'],
        }
        tool = runtime['profile_tools']['masscan']
        return {
            'schema_version': 1, 'status': 'completed', 'execution_ref': request['execution_ref'],
            'authorization_ref': request['authorization_ref'], 'scope_ref': request['scope_ref'],
            'capability_id': 'network.masscan', 'target': request['target'], 'options': options,
            'tool': 'masscan', 'exit_code': int(process.returncode or 0),
            'stdout': b''.join(stdout_chunks).decode('utf-8', errors='replace'),
            'stderr': b''.join(stderr_chunks).decode('utf-8', errors='replace'),
            'duration_ms': int((time.monotonic() - started) * 1000),
            'runtime': {
                'provider': 'aegis-kali-network-masscan', 'profile': 'network',
                'runner_version': runtime.get('runner_version'), 'build_commit': runtime.get('build_commit'),
                'base_image_digest': runtime.get('base_image_digest'),
                'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                'dispatch_state': runtime.get('dispatch_state'),
                'dispatch_capabilities': runtime.get('dispatch_capabilities'),
                'tool': 'masscan', 'tool_version': tool.get('version'), 'tool_source': tool.get('source'),
                'linux_privilege': runtime['_linux_privilege'],
                'binding': {
                    'authorization_ref': request['authorization_ref'], 'scope_ref': request['scope_ref'],
                    'target': request['target'], **options,
                },
            },
        }
    finally:
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
        if record is not None:
            _remove_execution(request['execution_ref'], record)
        _ACTIVE_LIMIT.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisMasscanProvider/1'

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
        return hmac.compare_digest(self.headers.get('X-Aegis-Masscan-Token', ''), _provider_auth_token())

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
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ProtocolError('request body must be valid JSON') from exc
        if not isinstance(payload, dict):
            raise ProtocolError('request body must be a JSON object')
        return payload

    def do_GET(self) -> None:
        if self.path == '/healthz':
            try:
                runtime = _runtime_contract()
                self._json(HTTPStatus.OK, {'status': 'ok', 'profile': runtime['profile'], 'capability_id': 'network.masscan'})
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
                        'provider': 'aegis-kali-network-masscan', 'profile': 'network',
                        'runner_version': runtime.get('runner_version'), 'build_commit': runtime.get('build_commit'),
                        'base_image_digest': runtime.get('base_image_digest'),
                        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                        'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                        'dispatch_state': runtime.get('dispatch_state'),
                        'dispatch_capabilities': runtime.get('dispatch_capabilities'),
                        'linux_privilege': runtime['_linux_privilege'],
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
            if self.path == '/v1/execute':
                runtime = _runtime_contract()
                request = _validate_request(self._body(), runtime)
                self._json(HTTPStatus.OK, _execute(request, runtime))
                return
            match = re.fullmatch(r'/v1/executions/([A-Za-z0-9:._-]{1,255})/control', self.path)
            if match:
                payload = self._body()
                unknown = sorted(set(payload) - {'control_token', 'state'})
                if unknown:
                    raise ProtocolError(f'unsupported control fields: {unknown}')
                token = str(payload.get('control_token') or '')
                if not _TOKEN_RE.fullmatch(token):
                    raise ProtocolError('control_token is missing or invalid')
                state = str(payload.get('state') or '').strip()
                current = _control_execution(match.group(1), token, state)
                self._json(HTTPStatus.OK, {'status': 'ok', 'state': current})
                return
            self._json(HTTPStatus.NOT_FOUND, {'status': 'not_found'})
        except ProtocolError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {'status': 'rejected', 'error': str(exc)})
        except ExecutionCancelled as exc:
            self._json(HTTPStatus.CONFLICT, {'status': 'cancelled', 'error': str(exc)})
        except TimeoutError as exc:
            self._json(HTTPStatus.GATEWAY_TIMEOUT, {'status': 'failed', 'error': str(exc)})
        except Exception as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {'status': 'failed', 'error': str(exc)})


def main() -> int:
    if _LISTEN_HOST != '127.0.0.1':
        raise SystemExit('Masscan provider must bind to 127.0.0.1')
    if _LISTEN_PORT < 1024 or _LISTEN_PORT > 65535:
        raise SystemExit('AEGIS_MASSCAN_LISTEN_PORT must be between 1024 and 65535')
    _provider_auth_token()
    _runtime_contract()
    server = ThreadingHTTPServer((_LISTEN_HOST, _LISTEN_PORT), Handler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
