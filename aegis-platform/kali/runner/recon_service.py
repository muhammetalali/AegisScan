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
from typing import Any, BinaryIO

RUNTIME_MANIFEST = Path('/opt/aegis-runner/runtime-manifest.json')
TOOL_MANIFEST = Path('/opt/aegis-runner/tool-manifest.json')
MAX_REQUEST_BYTES = 64 * 1024
MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_ACTIVE_EXECUTIONS = 2
_LISTEN_HOST = os.environ.get('AEGIS_RECON_LISTEN_HOST', '127.0.0.1')
_LISTEN_PORT = int(os.environ.get('AEGIS_RECON_LISTEN_PORT', '18765'))
_REF_RE = re.compile(r'^[A-Za-z0-9:._-]{1,255}$')
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_LABEL_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')

CAPABILITY_TO_TOOL = {
    'recon.amass': 'amass',
    'recon.subfinder': 'subfinder',
    'recon.dnsenum': 'dnsenum',
    'recon.fierce': 'fierce',
}
AMASS_RUNTIME_PATH = '/usr/local/bin/aegis-amass-runtime'

TOOL_PATHS = {
    'amass': '/usr/local/bin/amass',
    'subfinder': '/usr/local/bin/subfinder',
    'dnsenum': '/usr/bin/dnsenum',
    'fierce': '/usr/bin/fierce',
}
CAPABILITY_TIMEOUT_MAX = {
    'recon.amass': 1830,
    'recon.subfinder': 600,
    'recon.dnsenum': 600,
    'recon.fierce': 600,
}


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
    payload = _load_json_bytes(raw)
    return payload


def _sha256(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def _provider_auth_token() -> str:
    token = os.environ.get('AEGIS_KALI_RECON_AUTH_TOKEN', '').strip()
    if not _TOKEN_RE.fullmatch(token):
        raise RuntimeError('AEGIS_KALI_RECON_AUTH_TOKEN must be a 64-character lowercase hex token')
    return token


def _runtime_contract() -> dict[str, Any]:
    runtime = _load_manifest(RUNTIME_MANIFEST)
    if runtime.get('runtime') != 'aegis-kali' or runtime.get('profile') != 'recon':
        raise RuntimeError('recon provider requires the aegis-kali recon profile')
    if runtime.get('dispatch_enabled') is not True:
        raise RuntimeError('recon provider dispatch is not enabled by the runtime manifest')
    if runtime.get('dispatch_state') != 'semantic-recon-provider':
        raise RuntimeError('unexpected recon provider dispatch state')
    if runtime.get('tool_manifest_digest') != _sha256(TOOL_MANIFEST):
        raise RuntimeError('runtime/tool manifest digest mismatch')
    capabilities = runtime.get('profile_capabilities')
    tools = runtime.get('profile_tools')
    if not isinstance(capabilities, list) or not isinstance(tools, dict):
        raise RuntimeError('recon runtime manifest is incomplete')
    if set(capabilities) != set(CAPABILITY_TO_TOOL):
        raise RuntimeError('recon runtime capability set does not match the provider adapter')
    if set(CAPABILITY_TO_TOOL.values()) - set(tools):
        raise RuntimeError('recon runtime tool set is incomplete')
    for tool, path in TOOL_PATHS.items():
        if not Path(path).is_file() or not os.access(path, os.X_OK):
            raise RuntimeError(f'required recon binary is unavailable: {tool}')
    return runtime


def _canonical_domain(value: Any) -> str:
    target = str(value or '').strip().lower()
    if not target or len(target) > 253 or any(ch in target for ch in '\r\n\x00/:'):
        raise ProtocolError('target must be a canonical domain name')
    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        raise ProtocolError('recon provider requires a domain asset, not an IP address')
    labels = target.split('.')
    if len(labels) < 2 or any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise ProtocolError('target must be a canonical domain name')
    return target


def _bounded_ref(name: str, value: Any) -> str:
    ref = str(value or '').strip()
    if not _REF_RE.fullmatch(ref):
        raise ProtocolError(f'{name} is missing or invalid')
    return ref


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
    capability_id = str(payload.get('capability_id') or '').strip()
    if capability_id not in CAPABILITY_TO_TOOL:
        raise ProtocolError('capability is not registered for the recon provider')
    if capability_id not in runtime['profile_capabilities']:
        raise ProtocolError('capability is not allowed by the recon runtime manifest')
    tool = CAPABILITY_TO_TOOL[capability_id]
    if tool not in runtime['profile_tools']:
        raise ProtocolError('capability tool is not present in the recon runtime manifest')
    token = str(payload.get('control_token') or '')
    if not _TOKEN_RE.fullmatch(token):
        raise ProtocolError('control_token is missing or invalid')
    options = payload.get('options', {})
    if not isinstance(options, dict):
        raise ProtocolError('options must be a JSON object')
    timeout_raw = payload.get('timeout_seconds')
    if isinstance(timeout_raw, bool):
        raise ProtocolError('timeout_seconds must be an integer')
    try:
        timeout_seconds = int(timeout_raw)
    except (TypeError, ValueError) as exc:
        raise ProtocolError('timeout_seconds must be an integer') from exc
    max_timeout = CAPABILITY_TIMEOUT_MAX[capability_id]
    if timeout_seconds < 5 or timeout_seconds > max_timeout:
        raise ProtocolError(f'timeout_seconds must be between 5 and {max_timeout}')
    normalized_options: dict[str, Any] = {}
    if capability_id == 'recon.amass':
        unknown_options = sorted(set(options) - {'timeout_minutes'})
        if unknown_options:
            raise ProtocolError(f'unsupported recon.amass options: {unknown_options}')
        raw_minutes = options.get('timeout_minutes', 5)
        if isinstance(raw_minutes, bool):
            raise ProtocolError('timeout_minutes must be an integer')
        try:
            minutes = int(raw_minutes)
        except (TypeError, ValueError) as exc:
            raise ProtocolError('timeout_minutes must be an integer') from exc
        if minutes < 1 or minutes > 30:
            raise ProtocolError('timeout_minutes must be between 1 and 30')
        normalized_options['timeout_minutes'] = minutes
    elif options:
        raise ProtocolError(f'{capability_id} does not accept provider options')
    return {
        'execution_ref': _bounded_ref('execution_ref', payload.get('execution_ref')),
        'authorization_ref': _bounded_ref('authorization_ref', payload.get('authorization_ref')),
        'scope_ref': _bounded_ref('scope_ref', payload.get('scope_ref')),
        'control_token': token,
        'capability_id': capability_id,
        'tool': tool,
        'target': _canonical_domain(payload.get('target')),
        'options': normalized_options,
        'timeout_seconds': timeout_seconds,
    }


def _build_command(request: dict[str, Any]) -> list[str]:
    capability_id = request['capability_id']
    target = request['target']
    tool = request['tool']
    binary = TOOL_PATHS[tool]
    if capability_id == 'recon.amass':
        return [
            AMASS_RUNTIME_PATH,
            '--target',
            target,
            '--timeout-minutes',
            str(request['options']['timeout_minutes']),
        ]
    if capability_id == 'recon.subfinder':
        return [binary, '-d', target, '-silent', '-duc']
    if capability_id == 'recon.dnsenum':
        return [binary, target]
    if capability_id == 'recon.fierce':
        return [binary, '--domain', target]
    raise ProtocolError('capability has no recon command adapter')


def _sanitized_environment() -> dict[str, str]:
    return {
        'HOME': '/tmp/aegis-home',
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'NO_COLOR': '1',
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'TMPDIR': '/tmp',
        'XDG_CACHE_HOME': '/tmp/aegis-home/.cache',
        'XDG_CONFIG_HOME': '/tmp/aegis-home/.config',
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
    command = _build_command(request)
    os.makedirs('/tmp/aegis-home/.config', mode=0o700, exist_ok=True)
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    overflow = threading.Event()
    started = time.monotonic()
    acquired = _ACTIVE_LIMIT.acquire(timeout=5)
    if not acquired:
        raise RuntimeError('recon provider concurrency limit reached')
    process: subprocess.Popen[bytes] | None = None
    record: ActiveExecution | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            env=_sanitized_environment(),
            cwd='/tmp',
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
                raise OutputLimitExceeded('recon provider output exceeded the 2 MiB stream limit')
            if time.monotonic() >= deadline:
                _terminate_process_group(process)
                raise TimeoutError('recon provider execution timed out')
            with record.lock:
                cancelled = record.state == 'cancelled'
            if cancelled:
                raise ExecutionCancelled('recon provider execution cancelled')
            time.sleep(0.05)
        for thread in readers:
            thread.join(timeout=2)
        with record.lock:
            if record.state == 'cancelled':
                raise ExecutionCancelled('recon provider execution cancelled')
        if overflow.is_set():
            raise OutputLimitExceeded('recon provider output exceeded the 2 MiB stream limit')
        stdout = b''.join(stdout_chunks).decode('utf-8', errors='replace')
        stderr = b''.join(stderr_chunks).decode('utf-8', errors='replace')
        tool_meta = runtime['profile_tools'][request['tool']]
        return {
            'schema_version': 1,
            'status': 'completed',
            'execution_ref': request['execution_ref'],
            'capability_id': request['capability_id'],
            'target': request['target'],
            'tool': request['tool'],
            'exit_code': int(process.returncode or 0),
            'stdout': stdout,
            'stderr': stderr,
            'duration_ms': int((time.monotonic() - started) * 1000),
            'runtime': {
                'provider': 'aegis-kali-recon',
                'profile': runtime['profile'],
                'runner_version': runtime.get('runner_version'),
                'base_image_digest': runtime.get('base_image_digest'),
                'build_commit': runtime.get('build_commit'),
                'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                'tool': request['tool'],
                'tool_version': tool_meta.get('version'),
                'tool_source': tool_meta.get('source'),
            },
        }
    finally:
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
        if record is not None:
            _remove_execution(request['execution_ref'], record)
        _ACTIVE_LIMIT.release()


class ReconHandler(BaseHTTPRequestHandler):
    server_version = 'AegisReconProvider/1'

    def log_message(self, format: str, *args: Any) -> None:
        # Do not log request bodies, targets, control tokens, or authorization refs.
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict[str, Any]:
        raw_length = self.headers.get('Content-Length')
        if raw_length is None:
            raise ProtocolError('Content-Length is required')
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ProtocolError('Content-Length must be an integer') from exc
        if length < 2 or length > MAX_REQUEST_BYTES:
            raise ProtocolError('request body exceeds the provider limit')
        content_type = self.headers.get_content_type()
        if content_type != 'application/json':
            raise ProtocolError('Content-Type must be application/json')
        return _load_json_bytes(self.rfile.read(length))

    def do_GET(self) -> None:
        if self.path == '/healthz':
            try:
                runtime = _runtime_contract()
                self._json(HTTPStatus.OK, {
                    'status': 'ok',
                    'provider': 'aegis-kali-recon',
                    'profile': runtime['profile'],
                    'dispatch_enabled': True,
                    'build_commit': runtime.get('build_commit'),
                })
            except Exception as exc:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {'status': 'unhealthy', 'error': str(exc)})
            return

        if self.path == '/v1/runtime':
            try:
                expected_token = _provider_auth_token()
                received_token = self.headers.get('X-Aegis-Recon-Token', '')
                if not hmac.compare_digest(received_token, expected_token):
                    self._json(HTTPStatus.UNAUTHORIZED, {'status': 'unauthorized'})
                    return
                runtime = _runtime_contract()
                self._json(HTTPStatus.OK, {
                    'status': 'ok',
                    'runtime': {
                        'provider': 'aegis-kali-recon',
                        'profile': runtime['profile'],
                        'runner_version': runtime.get('runner_version'),
                        'build_commit': runtime.get('build_commit'),
                        'base_image_digest': runtime.get('base_image_digest'),
                        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
                        'runtime_manifest_digest': _sha256(RUNTIME_MANIFEST),
                    },
                })
            except Exception as exc:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    {'status': 'unhealthy', 'error': str(exc)},
                )
            return

        self._json(HTTPStatus.NOT_FOUND, {'status': 'not_found'})

    def do_POST(self) -> None:
        try:
            expected_token = _provider_auth_token()
            received_token = self.headers.get('X-Aegis-Recon-Token', '')
            if not hmac.compare_digest(received_token, expected_token):
                self._json(HTTPStatus.UNAUTHORIZED, {'status': 'unauthorized'})
                return
            if self.path == '/v1/execute':
                runtime = _runtime_contract()
                request = _validate_request(self._body(), runtime)
                try:
                    result = _execute(request, runtime)
                except ExecutionCancelled:
                    result = {
                        'schema_version': 1,
                        'status': 'cancelled',
                        'execution_ref': request['execution_ref'],
                        'capability_id': request['capability_id'],
                    }
                self._json(HTTPStatus.OK, result)
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
                state = _control_execution(match.group(1), token, str(payload.get('state') or ''))
                self._json(HTTPStatus.OK, {'status': 'ok', 'state': state})
                return
            self._json(HTTPStatus.NOT_FOUND, {'status': 'not_found'})
        except ProtocolError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {'status': 'rejected', 'error': str(exc)})
        except OutputLimitExceeded as exc:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {'status': 'failed', 'error': str(exc)})
        except TimeoutError as exc:
            self._json(HTTPStatus.GATEWAY_TIMEOUT, {'status': 'failed', 'error': str(exc)})
        except Exception as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {'status': 'failed', 'error': str(exc)})


def main() -> int:
    if _LISTEN_HOST != '127.0.0.1':
        raise SystemExit('recon provider must bind to 127.0.0.1 inside the shared scanner namespace')
    if _LISTEN_PORT < 1024 or _LISTEN_PORT > 65535:
        raise SystemExit('AEGIS_RECON_LISTEN_PORT must be between 1024 and 65535')
    _provider_auth_token()
    _runtime_contract()
    server = ThreadingHTTPServer((_LISTEN_HOST, _LISTEN_PORT), ReconHandler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
