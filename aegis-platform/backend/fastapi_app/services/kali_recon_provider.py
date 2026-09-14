from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_AUTH_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_SHA256_RE = re.compile(r'^sha256:[a-f0-9]{64}$')
_COMMIT_RE = re.compile(r'^[a-f0-9]{40}$')
_RUNTIME_TEXT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,254}$')
_RECON_TOOL_BY_CAPABILITY = {
    'recon.amass': 'amass',
    'recon.subfinder': 'subfinder',
    'recon.dnsenum': 'dnsenum',
    'recon.fierce': 'fierce',
}
_RECON_CAPABILITIES = frozenset(_RECON_TOOL_BY_CAPABILITY)


class KaliReconProviderError(RuntimeError):
    pass


class KaliReconProviderCancelled(KaliReconProviderError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def provider_mode() -> str:
    mode = os.getenv('AEGIS_RECON_PROVIDER', 'legacy').strip().lower()
    if mode not in {'legacy', 'kali'}:
        raise KaliReconProviderError('AEGIS_RECON_PROVIDER must be legacy or kali')
    return mode


def should_use_kali_recon(capability_id: str) -> bool:
    return capability_id in _RECON_CAPABILITIES and provider_mode() == 'kali'


def _auth_token() -> str:
    token = os.getenv('AEGIS_KALI_RECON_AUTH_TOKEN', '').strip()
    if not _AUTH_TOKEN_RE.fullmatch(token):
        raise KaliReconProviderError('AEGIS_KALI_RECON_AUTH_TOKEN must be a 64-character lowercase hex token')
    return token


def _direct_opener():
    # Never let HTTP_PROXY/HTTPS_PROXY redirect authorization-bound loopback traffic.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _base_url() -> str:
    raw = os.getenv('AEGIS_KALI_RECON_URL', 'http://127.0.0.1:18765').strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1':
        raise KaliReconProviderError('AEGIS_KALI_RECON_URL must be an http 127.0.0.1 endpoint')
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise KaliReconProviderError('AEGIS_KALI_RECON_URL must not contain credentials, query, or fragment')
    if parsed.path not in {'', '/'}:
        raise KaliReconProviderError('AEGIS_KALI_RECON_URL must not contain a path')
    port = parsed.port or 80
    if port < 1024 or port > 65535:
        raise KaliReconProviderError('AEGIS_KALI_RECON_URL port must be between 1024 and 65535')
    return f'http://127.0.0.1:{port}'


def _bounded_runtime_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _RUNTIME_TEXT_RE.fullmatch(value):
        raise KaliReconProviderError(f'Kali recon provider runtime {name} is missing or invalid')
    return value


def _configured_expected(name: str, validator: re.Pattern[str] | None = None) -> str | None:
    value = os.getenv(name, '').strip()
    if not value:
        return None
    if validator is not None and not validator.fullmatch(value):
        raise KaliReconProviderError(f'{name} is invalid')
    if validator is None and not _RUNTIME_TEXT_RE.fullmatch(value):
        raise KaliReconProviderError(f'{name} is invalid')
    return value


def _validate_runtime_provenance(*, capability_id: str, top_level_tool: Any, runtime: Any) -> None:
    if not isinstance(runtime, dict):
        raise KaliReconProviderError('Kali recon provider provenance is missing or invalid')
    expected_tool = _RECON_TOOL_BY_CAPABILITY[capability_id]
    if top_level_tool != expected_tool:
        raise KaliReconProviderError('Kali recon provider tool binding mismatch')
    if runtime.get('provider') != 'aegis-kali-recon':
        raise KaliReconProviderError('Kali recon provider provenance provider is invalid')
    if runtime.get('profile') != 'recon':
        raise KaliReconProviderError('Kali recon provider provenance profile mismatch')
    if runtime.get('tool') != expected_tool:
        raise KaliReconProviderError('Kali recon provider provenance tool mismatch')

    actual = {
        'runner_version': _bounded_runtime_text('runner_version', runtime.get('runner_version')),
        'build_commit': runtime.get('build_commit'),
        'base_image_digest': runtime.get('base_image_digest'),
        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
    }
    _bounded_runtime_text('tool_version', runtime.get('tool_version'))
    _bounded_runtime_text('tool_source', runtime.get('tool_source'))

    if not isinstance(actual['build_commit'], str) or not _COMMIT_RE.fullmatch(actual['build_commit']):
        raise KaliReconProviderError('Kali recon provider runtime build_commit is missing or invalid')
    if not isinstance(actual['base_image_digest'], str) or not _SHA256_RE.fullmatch(actual['base_image_digest']):
        raise KaliReconProviderError('Kali recon provider runtime base_image_digest is missing or invalid')
    if not isinstance(actual['tool_manifest_digest'], str) or not _SHA256_RE.fullmatch(actual['tool_manifest_digest']):
        raise KaliReconProviderError('Kali recon provider runtime tool_manifest_digest is missing or invalid')

    expected = {
        'runner_version': _configured_expected('AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION'),
        'build_commit': _configured_expected('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', _COMMIT_RE),
        'base_image_digest': _configured_expected('AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST', _SHA256_RE),
        'tool_manifest_digest': _configured_expected('AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST', _SHA256_RE),
    }
    for field, value in expected.items():
        if value is not None and actual[field] != value:
            raise KaliReconProviderError(f'Kali recon provider pinned {field} mismatch')


def _request_json(method: str, path: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    request = urllib.request.Request(
        _base_url() + path,
        data=body,
        method=method,
        headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Aegis-Recon-Token': _auth_token(),
        },
    )
    opener = _direct_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raw = exc.read(8192)
        detail = raw.decode('utf-8', errors='replace').strip()
        raise KaliReconProviderError(f'Kali recon provider rejected request ({exc.code}): {detail[:2000]}') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise KaliReconProviderError(f'Kali recon provider is unavailable: {exc}') from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise KaliReconProviderError('Kali recon provider response exceeded 4 MiB')
    try:
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KaliReconProviderError('Kali recon provider returned invalid JSON') from exc
    if not isinstance(result, dict):
        raise KaliReconProviderError('Kali recon provider response must be a JSON object')
    return result


def _control(execution_ref: str, control_token: str, state: str) -> None:
    path = f'/v1/executions/{urllib.parse.quote(execution_ref, safe=":._-")}/control'
    last_error: KaliReconProviderError | None = None
    for attempt in range(20):
        try:
            result = _request_json(
                'POST',
                path,
                {'control_token': control_token, 'state': state},
                timeout=3,
            )
        except KaliReconProviderError as exc:
            last_error = exc
            if 'execution_ref is not active' not in str(exc) or attempt == 19:
                raise
            time.sleep(0.05)
            continue
        if result.get('status') != 'ok' or result.get('state') != state:
            raise KaliReconProviderError(f'Kali recon provider did not enter requested state {state!r}')
        return
    if last_error is not None:  # pragma: no cover - loop always raises or returns.
        raise last_error


def execute_kali_recon(
    *,
    capability_id: str,
    target: str,
    options: dict[str, Any],
    timeout_seconds: int,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
    poll_interval: float,
) -> dict[str, Any]:
    if capability_id not in _RECON_CAPABILITIES:
        raise KaliReconProviderError(f'{capability_id} is not a Kali recon provider capability')
    for name, value in (
        ('execution_ref', execution_ref),
        ('authorization_ref', authorization_ref),
        ('scope_ref', scope_ref),
    ):
        if not value or len(value) > 255:
            raise KaliReconProviderError(f'{name} is required for Kali recon execution')
    control_token = secrets.token_hex(32)
    request_payload = {
        'schema_version': 1,
        'execution_ref': execution_ref,
        'authorization_ref': authorization_ref,
        'scope_ref': scope_ref,
        'control_token': control_token,
        'capability_id': capability_id,
        'target': target,
        'options': options,
        'timeout_seconds': int(timeout_seconds),
    }
    holder: dict[str, Any] = {}

    def invoke() -> None:
        try:
            holder['result'] = _request_json(
                'POST',
                '/v1/execute',
                request_payload,
                timeout=float(timeout_seconds + 15),
            )
        except BaseException as exc:  # captured and re-raised on the caller thread
            holder['error'] = exc

    thread = threading.Thread(target=invoke, name=f'kali-recon-{execution_ref[:32]}', daemon=True)
    thread.start()
    previous_state = 'running'
    cancelled = False
    control_error: BaseException | None = None
    try:
        while thread.is_alive():
            state = state_getter() if state_getter is not None else 'running'
            if state not in {'running', 'paused', 'cancelled'}:
                state = 'running'
            if state != previous_state:
                try:
                    _control(execution_ref, control_token, state)
                except BaseException as exc:
                    control_error = exc
                    try:
                        _control(execution_ref, control_token, 'cancelled')
                    except BaseException:
                        pass
                    break
                previous_state = state
            if state == 'cancelled':
                cancelled = True
                break
            thread.join(timeout=max(0.05, min(float(poll_interval), 1.0)))
        if control_error is not None:
            raise KaliReconProviderError(f'Kali recon provider control failed: {control_error}') from control_error
        if cancelled:
            thread.join(timeout=10)
            raise KaliReconProviderCancelled('Kali recon capability execution cancelled')
        thread.join(timeout=1)
        if thread.is_alive():
            try:
                _control(execution_ref, control_token, 'cancelled')
            except BaseException:
                pass
            raise KaliReconProviderError('Kali recon provider request did not terminate cleanly')
        if 'error' in holder:
            error = holder['error']
            if isinstance(error, BaseException):
                raise error
            raise KaliReconProviderError('Kali recon provider request failed')
        result = holder.get('result')
        if not isinstance(result, dict):
            raise KaliReconProviderError('Kali recon provider returned no result')
        if result.get('status') == 'cancelled':
            raise KaliReconProviderCancelled('Kali recon capability execution cancelled')
        if result.get('status') != 'completed':
            raise KaliReconProviderError('Kali recon provider did not complete the execution')
        if result.get('schema_version') != 1:
            raise KaliReconProviderError('Kali recon provider response schema mismatch')
        if result.get('execution_ref') != execution_ref or result.get('capability_id') != capability_id:
            raise KaliReconProviderError('Kali recon provider response binding mismatch')
        if result.get('target') != target:
            raise KaliReconProviderError('Kali recon provider target binding mismatch')
        _validate_runtime_provenance(
            capability_id=capability_id,
            top_level_tool=result.get('tool'),
            runtime=result.get('runtime'),
        )
        if not isinstance(result.get('exit_code'), int):
            raise KaliReconProviderError('Kali recon provider exit_code is invalid')
        if not isinstance(result.get('stdout'), str) or not isinstance(result.get('stderr'), str):
            raise KaliReconProviderError('Kali recon provider output fields are invalid')
        return result
    finally:
        if previous_state == 'paused' and thread.is_alive():
            try:
                _control(execution_ref, control_token, 'cancelled')
            except BaseException:
                pass
