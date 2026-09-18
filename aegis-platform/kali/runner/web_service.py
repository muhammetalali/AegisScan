#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

RUNTIME_MANIFEST = Path('/opt/aegis-runner/runtime-manifest.json')
TOOL_MANIFEST = Path('/opt/aegis-runner/tool-manifest.json')
NUCLEI = '/usr/local/bin/nuclei'
TEMPLATES = Path(os.environ.get('NUCLEI_TEMPLATES_DIR', '/opt/nuclei-templates'))
MAX_REQUEST_BYTES = 64 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_ACTIVE_EXECUTIONS = 2
_LISTEN_HOST = os.environ.get('AEGIS_WEB_LISTEN_HOST', '127.0.0.1')
_LISTEN_PORT = int(os.environ.get('AEGIS_WEB_LISTEN_PORT', '18770'))
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_REF_RE = re.compile(r'^[A-Za-z0-9:._/-]{1,255}$')


class ProtocolError(ValueError):
    pass


class OutputLimitExceeded(RuntimeError):
    pass


class ExecutionCancelled(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f'duplicate JSON field: {key}')
        result[key] = value
    return result


def _load_json_bytes(data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode('utf-8'), object_pairs_hook=_reject_duplicate_pairs)
    except UnicodeDecodeError as exc:
        raise ProtocolError('request body must be UTF-8') from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError('request body must be valid JSON') from exc
    if not isinstance(payload, dict):
        raise ProtocolError('request body must be a JSON object')
    return payload


def _load_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_REQUEST_BYTES:
        raise RuntimeError(f'manifest too large: {path}')
    return _load_json_bytes(raw)


def _sha256(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def _provider_auth_token() -> str:
    token = os.environ.get('AEGIS_KALI_WEB_AUTH_TOKEN', '').strip()
    if not _TOKEN_RE.fullmatch(token):
        raise RuntimeError('AEGIS_KALI_WEB_AUTH_TOKEN must be 64 lowercase hex characters')
    return token


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

    for name, value in caps.items():
        if value != 0:
            raise RuntimeError(f'{name} must be zero for the web provider')
    if values['NoNewPrivs'] != '1':
        raise RuntimeError('web provider requires no_new_privs')
    if os.geteuid() == 0:
        raise RuntimeError('web provider must run as non-root')

    return {
        'uid': os.geteuid(),
        'effective': f"{caps['CapEff']:016x}",
        'permitted': f"{caps['CapPrm']:016x}",
        'bounding': f"{caps['CapBnd']:016x}",
        'inheritable': f"{caps['CapInh']:016x}",
        'ambient': f"{caps['CapAmb']:016x}",
        'no_new_privs': True,
        'allowed_capabilities': [],
    }


def _runtime_contract() -> dict[str, Any]:
    runtime = _load_manifest(RUNTIME_MANIFEST)
    if runtime.get('runtime') != 'aegis-kali' or runtime.get('profile') != 'web':
        raise RuntimeError('web provider requires the aegis-kali web profile')
    if runtime.get('dispatch_enabled') is not True:
        raise RuntimeError('web provider dispatch is not enabled by the runtime manifest')
    if runtime.get('dispatch_state') != 'semantic-web-provider':
        raise RuntimeError('unexpected web provider dispatch state')
    if runtime.get('dispatch_capabilities') != ['web.nuclei']:
        raise RuntimeError('web provider may dispatch only web.nuclei during canary phase')
    if runtime.get('tool_manifest_digest') != _sha256(TOOL_MANIFEST):
        raise RuntimeError('runtime/tool manifest digest mismatch')

    capabilities = runtime.get('profile_capabilities')
    tools = runtime.get('profile_tools')
    if not isinstance(capabilities, list) or 'web.nuclei' not in capabilities:
        raise RuntimeError('web.nuclei is absent from runtime capability placement')
    if not isinstance(tools, dict):
        raise RuntimeError('web tool provenance is absent from runtime manifest')
    nuclei = tools.get('nuclei')
    templates = tools.get('nuclei-templates')
    if not isinstance(nuclei, dict) or nuclei.get('version') != '3.11.1':
        raise RuntimeError('pinned Nuclei provenance is absent or invalid')
    if (
        not isinstance(templates, dict)
        or templates.get('commit') != '0cb51d4bfae945e5ec2644fc8c2d2e6ea84bbffe'
    ):
        raise RuntimeError('pinned Nuclei template provenance is absent or invalid')
    if not Path(NUCLEI).is_file() or not os.access(NUCLEI, os.X_OK):
        raise RuntimeError('pinned Nuclei binary is unavailable')
    if not TEMPLATES.is_dir() or TEMPLATES.is_symlink():
        raise RuntimeError('Nuclei template root is unavailable or invalid')

    runtime = dict(runtime)
    runtime['_linux_privilege'] = _linux_privilege_boundary()
    return runtime


def _canonical_target(value: Any) -> str:
    target = str(value or '').strip()
    if not target or len(target) > 4096 or any(ch in target for ch in '\r\n\x00'):
        raise ProtocolError('target is missing or invalid')
    parsed = urlsplit(target)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ProtocolError('target must be an http/https URL')
    if parsed.username is not None or parsed.password is not None:
        raise ProtocolError('target URL must not contain userinfo')
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ProtocolError('target URL port is invalid') from exc
    return target


def _bounded_ref(name: str, value: Any) -> str:
    ref = str(value or '').strip()
    if not _REF_RE.fullmatch(ref):
        raise ProtocolError(f'{name} is missing or invalid')
    return ref


def _validate_request(payload: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        'schema_version',
        'execution_ref',
        'authorization_ref',
        'scope_ref',
        'control_token',
        'capability_id',
        'target',
        'options',
        'timeout_seconds',
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ProtocolError(f'unsupported request fields: {unknown}')
    if payload.get('schema_version') != 1:
        raise ProtocolError('unsupported request schema_version')
    if payload.get('capability_id') != 'web.nuclei':
        raise ProtocolError('web provider accepts only web.nuclei during canary phase')
    if 'web.nuclei' not in runtime['dispatch_capabilities']:
        raise ProtocolError('web.nuclei is not dispatchable by this runtime')
    token = str(payload.get('control_token') or '')
    if not _TOKEN_RE.fullmatch(token):
        raise ProtocolError('control_token is missing or invalid')
    options = payload.get('options', {})
    if not isinstance(options, dict) or options:
        raise ProtocolError('web.nuclei does not accept provider options')
    raw_timeout = payload.get('timeout_seconds')
    if isinstance(raw_timeout, bool):
        raise ProtocolError('timeout_seconds must be an integer')
    try:
        timeout = int(raw_timeout)
    except (TypeError, ValueError) as exc:
        raise ProtocolError('timeout_seconds must be an integer') from exc
    if timeout < 5 or timeout > 600:
        raise ProtocolError('timeout_seconds must be between 5 and 600')
    return {
        'execution_ref': _bounded_ref('execution_ref', payload.get('execution_ref')),
        'authorization_ref': _bounded_ref('authorization_ref', payload.get('authorization_ref')),
        'scope_ref': _bounded_ref('scope_ref', payload.get('scope_ref')),
        'control_token': token,
        'capability_id': 'web.nuclei',
        'target': _canonical_target(payload.get('target')),
        'timeout_seconds': timeout,
    }


def _sanitized_env(root: str) -> dict[str, str]:
    home = Path(root) / 'home'
    config = Path(root) / 'config'
    cache = Path(root) / 'cache'
    for path in (home, config, cache):
        path.mkdir(mode=0o700)
    return {
        'HOME': str(home),
        'XDG_CONFIG_HOME': str(config),
        'XDG_CACHE_HOME': str(cache),
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'NO_COLOR': '1',
        'PATH': '/usr/local/bin:/usr/bin:/bin',
        'TMPDIR': root,
    }


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGCONT)
    except ProcessLookupError:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)
    except ProcessLookupError:
        pass


@dataclass
class ActiveExecution:
    token: str
    process: subprocess.Popen[bytes]
    state: str = 'running'
    lock: threading.Lock = field(default_factory=threading.Lock)


_ACTIVE: dict[str, ActiveExecution] = {}
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_LIMIT = threading.BoundedSemaphore(MAX_ACTIVE_EXECUTIONS)


def _stream_reader(stream: BinaryIO, chunks: list[bytes], overflow: threading.Event) -> None:
    total = 0
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            total += len(chunk)
            if total > MAX_STREAM_BYTES:
                overflow.set()
                return
            chunks.append(chunk)
    finally:
        try:
            stream.close()
        except OSError:
            pass


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


def _execute(request: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    started = time.monotonic()
    acquired = _ACTIVE_LIMIT.acquire(timeout=5)
    if not acquired:
        raise RuntimeError('web provider concurrency limit reached')
    process: subprocess.Popen[bytes] | None = None
    record: ActiveExecution | None = None
    holder: tempfile.TemporaryDirectory[str] | None = None
    try:
        holder = tempfile.TemporaryDirectory(prefix='aegis-nuclei-', dir='/tmp')
        command = [
            NUCLEI,
            '-u',
            request['target'],
            '-t',
            str(TEMPLATES),
            '-jsonl',
            '-silent',
            '-no-color',
            '-dr',
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            env=_sanitized_env(holder.name),
            cwd=holder.name,
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
                raise OutputLimitExceeded('web provider output exceeded the 8 MiB stream limit')
            if time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise TimeoutError('web provider execution timed out')
            with record.lock:
                cancelled = record.state == 'cancelled'
                paused = record.state == 'paused'
            if cancelled:
                raise ExecutionCancelled('web provider execution cancelled')
            time.sleep(0.05)
            if paused:
                deadline += 0.05
        for thread in readers:
            thread.join(timeout=2)
        with record.lock:
            if record.state == 'cancelled':
                raise ExecutionCancelled('web provider execution cancelled')
        if overflow.is_set():
            raise OutputLimitExceeded('web provider output exceeded the 8 MiB stream limit')
        stdout = b''.join(stdout_chunks).decode('utf-8', errors='replace')
        stderr = b''.join(stderr_chunks).decode('utf-8', errors='replace')
        tool = runtime['profile_tools']['nuclei']
        templates = runtime['profile_tools']['nuclei-templates']
        return {
            'schema_version': 1,
            'status': 'completed',
            'execution_ref': request['execution_ref'],
            'capability_id': 'web.nuclei',
            'target': request['target'],
            'tool': 'nuclei',
            'exit_code': int(process.returncode or 0),
            'stdout': stdout,
            'stderr': stderr,
            'duration_ms': int((time.monotonic() - started) * 1000),
            'runtime': {
                'provider': 'aegis-kali-web',
                'profile': 'web',
                'runner_version': runtime.get('runner_version'),
                'base_image_digest': runtime.get('base_image_digest'),
                'build_commit': runtime.get('build_commit'),
                'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                'dispatch_state': runtime.get('dispatch_state'),
                'dispatch_capabilities': runtime.get('dispatch_capabilities'),
                'tool': 'nuclei',
                'tool_version': tool.get('version'),
                'tool_source': tool.get('source'),
                'template_commit': templates.get('commit'),
                'linux_privilege': runtime['_linux_privilege'],
            },
        }
    finally:
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
        if record is not None:
            _remove_execution(request['execution_ref'], record)
        if holder is not None:
            holder.cleanup()
        _ACTIVE_LIMIT.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'AegisWebProvider/1'

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
            self.headers.get('X-Aegis-Web-Token', ''),
            _provider_auth_token(),
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
        return _load_json_bytes(self.rfile.read(length))

    def do_GET(self) -> None:
        if self.path == '/healthz':
            try:
                runtime = _runtime_contract()
                self._json(
                    HTTPStatus.OK,
                    {'status': 'ok', 'profile': runtime['profile'], 'provider': 'web'},
                )
            except Exception as exc:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {'status': 'unhealthy', 'error': str(exc)},
                )
            return
        if self.path == '/v1/runtime':
            if not self._authorized():
                self._json(HTTPStatus.UNAUTHORIZED, {'status': 'unauthorized'})
                return
            try:
                runtime = _runtime_contract()
                tool = runtime['profile_tools']['nuclei']
                templates = runtime['profile_tools']['nuclei-templates']
                self._json(
                    HTTPStatus.OK,
                    {
                        'status': 'ok',
                        'runtime': {
                            'provider': 'aegis-kali-web',
                            'profile': 'web',
                            'runner_version': runtime.get('runner_version'),
                            'build_commit': runtime.get('build_commit'),
                            'base_image_digest': runtime.get('base_image_digest'),
                            'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                            'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                            'dispatch_state': runtime.get('dispatch_state'),
                            'dispatch_capabilities': runtime.get('dispatch_capabilities'),
                            'tool': 'nuclei',
                            'tool_version': tool.get('version'),
                            'tool_source': tool.get('source'),
                            'template_commit': templates.get('commit'),
                            'linux_privilege': runtime['_linux_privilege'],
                        },
                    },
                )
            except Exception as exc:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {'status': 'unhealthy', 'error': str(exc)},
                )
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
            if self.path.startswith('/v1/executions/') and self.path.endswith('/control'):
                prefix = '/v1/executions/'
                execution_ref = self.path[len(prefix):-len('/control')]
                if not _REF_RE.fullmatch(execution_ref):
                    raise ProtocolError('execution_ref is missing or invalid')
                payload = self._body()
                allowed = {'control_token', 'state'}
                unknown = sorted(set(payload) - allowed)
                if unknown:
                    raise ProtocolError(f'unsupported control fields: {unknown}')
                token = str(payload.get('control_token') or '')
                if not _TOKEN_RE.fullmatch(token):
                    raise ProtocolError('control_token is missing or invalid')
                state = _control_execution(execution_ref, token, str(payload.get('state') or ''))
                self._json(HTTPStatus.OK, {'status': 'ok', 'state': state})
                return
            self._json(HTTPStatus.NOT_FOUND, {'status': 'not_found'})
        except ProtocolError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {'status': 'rejected', 'error': str(exc)})
        except ExecutionCancelled as exc:
            self._json(HTTPStatus.OK, {'status': 'cancelled', 'error': str(exc)})
        except TimeoutError as exc:
            self._json(HTTPStatus.GATEWAY_TIMEOUT, {'status': 'failed', 'error': str(exc)})
        except OutputLimitExceeded as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {'status': 'failed', 'error': str(exc)})
        except Exception as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {'status': 'failed', 'error': str(exc)})


def main() -> int:
    if _LISTEN_HOST != '127.0.0.1':
        raise SystemExit('web provider must bind to 127.0.0.1')
    if _LISTEN_PORT < 1024 or _LISTEN_PORT > 65535:
        raise SystemExit('AEGIS_WEB_LISTEN_PORT must be between 1024 and 65535')
    _provider_auth_token()
    _runtime_contract()
    server = ThreadingHTTPServer((_LISTEN_HOST, _LISTEN_PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
