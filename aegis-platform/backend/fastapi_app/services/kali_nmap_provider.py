from __future__ import annotations

import hashlib
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
from dataclasses import asdict, dataclass
from typing import Any

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_AUTH_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_SHA256_RE = re.compile(r'^sha256:[a-f0-9]{64}$')
_COMMIT_RE = re.compile(r'^[a-f0-9]{40}$')
_RUNTIME_TEXT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,254}$')
_ROUTING_SCHEMA = 'aegis.nmap-provider-routing.v1'
_CANARY_BUCKET_COUNT = 10_000
_MAX_CANARY_BPS = 2_500


@dataclass(frozen=True)
class NmapProviderDecision:
    schema: str
    mode: str
    capability_id: str
    selected_provider: str
    parity_approved: bool
    canary_bps: int
    bucket: int | None
    routing_key_digest: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class KaliNmapProviderError(RuntimeError):
    pass


class KaliNmapProviderCancelled(KaliNmapProviderError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def provider_mode() -> str:
    mode = os.getenv('AEGIS_NMAP_PROVIDER', 'legacy').strip().lower()
    if mode not in {'legacy', 'canary', 'default-kali', 'kali'}:
        raise KaliNmapProviderError('AEGIS_NMAP_PROVIDER must be legacy, canary, default-kali, or kali')
    return mode


def _canary_bps() -> int:
    raw = os.getenv('AEGIS_KALI_NMAP_CANARY_BPS', '0').strip()
    if not re.fullmatch(r'\d{1,5}', raw):
        raise KaliNmapProviderError('AEGIS_KALI_NMAP_CANARY_BPS must be an integer from 0 to 2500')
    value = int(raw)
    if value < 0 or value > _MAX_CANARY_BPS:
        raise KaliNmapProviderError('AEGIS_KALI_NMAP_CANARY_BPS must be an integer from 0 to 2500')
    return value


def _routing_key_digest(routing_key: str) -> tuple[str, int]:
    normalized = str(routing_key or '').strip()
    if not normalized or len(normalized) > 255:
        raise KaliNmapProviderError('A non-empty routing_key of at most 255 characters is required for Nmap canary routing')
    material = f'{_ROUTING_SCHEMA}\x00network.nmap\x00{normalized}'.encode('utf-8')
    digest = hashlib.sha256(material).hexdigest()
    return digest, int(digest[:16], 16) % _CANARY_BUCKET_COUNT


def nmap_provider_decision(*, routing_key: str | None = None) -> NmapProviderDecision:
    mode = provider_mode()
    if mode == 'legacy':
        return NmapProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id='network.nmap',
            selected_provider='legacy',
            parity_approved=True,
            canary_bps=0,
            bucket=None,
            routing_key_digest='',
            reason='legacy-default',
        )
    if mode == 'default-kali':
        return NmapProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id='network.nmap',
            selected_provider='kali',
            parity_approved=True,
            canary_bps=0,
            bucket=None,
            routing_key_digest='',
            reason='default-kali-parity-approved',
        )
    if mode == 'kali':
        return NmapProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id='network.nmap',
            selected_provider='kali',
            parity_approved=True,
            canary_bps=_CANARY_BUCKET_COUNT,
            bucket=None,
            routing_key_digest='',
            reason='explicit-kali-mode',
        )
    canary_bps = _canary_bps()
    if canary_bps == 0:
        return NmapProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id='network.nmap',
            selected_provider='legacy',
            parity_approved=True,
            canary_bps=0,
            bucket=None,
            routing_key_digest='',
            reason='canary-rollback-zero',
        )
    digest, bucket = _routing_key_digest(routing_key or '')
    selected = bucket < canary_bps
    return NmapProviderDecision(
        schema=_ROUTING_SCHEMA,
        mode=mode,
        capability_id='network.nmap',
        selected_provider='kali' if selected else 'legacy',
        parity_approved=True,
        canary_bps=canary_bps,
        bucket=bucket,
        routing_key_digest=digest,
        reason='canary-selected' if selected else 'canary-holdback',
    )


def _auth_token() -> str:
    token = os.getenv('AEGIS_KALI_NETWORK_AUTH_TOKEN', '').strip()
    if not _AUTH_TOKEN_RE.fullmatch(token):
        raise KaliNmapProviderError('AEGIS_KALI_NETWORK_AUTH_TOKEN must be a 64-character lowercase hex token')
    return token


def _direct_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _base_url() -> str:
    raw = os.getenv('AEGIS_KALI_NETWORK_URL', 'http://127.0.0.1:18766').strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1':
        raise KaliNmapProviderError('AEGIS_KALI_NETWORK_URL must be an http 127.0.0.1 endpoint')
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise KaliNmapProviderError('AEGIS_KALI_NETWORK_URL must not contain credentials, query, or fragment')
    if parsed.path not in {'', '/'}:
        raise KaliNmapProviderError('AEGIS_KALI_NETWORK_URL must not contain a path')
    port = parsed.port or 80
    if port < 1024 or port > 65535:
        raise KaliNmapProviderError('AEGIS_KALI_NETWORK_URL port must be between 1024 and 65535')
    return f'http://127.0.0.1:{port}'


def _bounded_runtime_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _RUNTIME_TEXT_RE.fullmatch(value):
        raise KaliNmapProviderError(f'Kali network provider runtime {name} is missing or invalid')
    return value


def _required_expected(name: str, validator: re.Pattern[str] | None = None) -> str:
    value = os.getenv(name, '').strip()
    if not value:
        raise KaliNmapProviderError(f'{name} is required when governed Kali Nmap execution is active')
    if validator is not None and not validator.fullmatch(value):
        raise KaliNmapProviderError(f'{name} is invalid')
    if validator is None and not _RUNTIME_TEXT_RE.fullmatch(value):
        raise KaliNmapProviderError(f'{name} is invalid')
    return value


def _trusted_expected_provenance() -> dict[str, str]:
    return {
        'runner_version': _required_expected('AEGIS_KALI_NETWORK_EXPECTED_RUNNER_VERSION'),
        'build_commit': _required_expected('AEGIS_KALI_NETWORK_EXPECTED_BUILD_COMMIT', _COMMIT_RE),
        'base_image_digest': _required_expected('AEGIS_KALI_NETWORK_EXPECTED_BASE_IMAGE_DIGEST', _SHA256_RE),
        'tool_manifest_digest': _required_expected('AEGIS_KALI_NETWORK_EXPECTED_TOOL_MANIFEST_DIGEST', _SHA256_RE),
        'image_digest': _required_expected('AEGIS_KALI_NETWORK_EXPECTED_IMAGE_DIGEST', _SHA256_RE),
        'runtime_manifest_digest': _required_expected('AEGIS_KALI_NETWORK_EXPECTED_RUNTIME_MANIFEST_DIGEST', _SHA256_RE),
    }


def _request_json(method: str, path: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    normalized_method = str(method or '').strip().upper()
    body = None
    headers = {'Accept': 'application/json', 'X-Aegis-Network-Token': _auth_token()}
    if normalized_method != 'GET':
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(_base_url() + path, data=body, method=normalized_method, headers=headers)
    try:
        with _direct_opener().open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(8192).decode('utf-8', errors='replace').strip()
        raise KaliNmapProviderError(f'Kali network provider rejected request ({exc.code}): {detail[:2000]}') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise KaliNmapProviderError(f'Kali network provider is unavailable: {exc}') from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise KaliNmapProviderError('Kali network provider response exceeded 4 MiB')
    try:
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KaliNmapProviderError('Kali network provider returned invalid JSON') from exc
    if not isinstance(result, dict):
        raise KaliNmapProviderError('Kali network provider response must be a JSON object')
    return result


def _validate_runtime(runtime: Any, expected: dict[str, str], *, top_level_tool: Any | None = None) -> dict[str, Any]:
    if not isinstance(runtime, dict):
        raise KaliNmapProviderError('Kali network provider provenance is missing or invalid')
    if runtime.get('provider') != 'aegis-kali-network':
        raise KaliNmapProviderError('Kali network provider provenance provider is invalid')
    if runtime.get('profile') != 'network':
        raise KaliNmapProviderError('Kali network provider provenance profile mismatch')
    if runtime.get('dispatch_state') != 'semantic-network-provider':
        raise KaliNmapProviderError('Kali network provider dispatch state mismatch')
    if runtime.get('dispatch_capabilities') != ['network.nmap']:
        raise KaliNmapProviderError('Kali network provider dispatch capability boundary mismatch')
    if top_level_tool is not None and top_level_tool != 'nmap':
        raise KaliNmapProviderError('Kali network provider tool binding mismatch')
    if runtime.get('tool') not in {None, 'nmap'}:
        raise KaliNmapProviderError('Kali network provider runtime tool mismatch')

    actual = {
        'runner_version': _bounded_runtime_text('runner_version', runtime.get('runner_version')),
        'build_commit': runtime.get('build_commit'),
        'base_image_digest': runtime.get('base_image_digest'),
        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
        'runtime_manifest_digest': runtime.get('runtime_manifest_digest'),
    }
    if not isinstance(actual['build_commit'], str) or not _COMMIT_RE.fullmatch(actual['build_commit']):
        raise KaliNmapProviderError('Kali network provider build_commit is missing or invalid')
    for field in ('base_image_digest', 'tool_manifest_digest', 'runtime_manifest_digest'):
        value = actual[field]
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise KaliNmapProviderError(f'Kali network provider {field} is missing or invalid')
    for field in ('runner_version', 'build_commit', 'base_image_digest', 'tool_manifest_digest', 'runtime_manifest_digest'):
        if actual[field] != expected[field]:
            raise KaliNmapProviderError(f'Kali network provider pinned {field} mismatch')

    privilege = runtime.get('linux_privilege')
    if not isinstance(privilege, dict):
        raise KaliNmapProviderError('Kali network provider Linux privilege attestation is missing')
    for name in ('effective', 'permitted', 'bounding'):
        if privilege.get(name) != '0000000000002000':
            raise KaliNmapProviderError(f'Kali network provider {name} capability boundary mismatch')
    if privilege.get('no_new_privs') is not True or privilege.get('allowed_capabilities') != ['CAP_NET_RAW']:
        raise KaliNmapProviderError('Kali network provider privilege boundary mismatch')

    trusted = dict(runtime)
    trusted['image_digest'] = expected['image_digest']
    trusted['runtime_manifest_digest'] = expected['runtime_manifest_digest']
    trusted['provenance_authority'] = 'control-plane-deployment-pins'
    return trusted


def _preflight_runtime_attestation(expected: dict[str, str]) -> None:
    payload = _request_json('GET', '/v1/runtime', {}, timeout=5)
    if payload.get('status') != 'ok':
        raise KaliNmapProviderError('Kali network provider runtime attestation is missing or invalid')
    _validate_runtime(payload.get('runtime'), expected)


def _control(execution_ref: str, control_token: str, state: str) -> None:
    path = f'/v1/executions/{urllib.parse.quote(execution_ref, safe=":._-")}/control'
    last_error: KaliNmapProviderError | None = None
    for attempt in range(20):
        try:
            result = _request_json('POST', path, {'control_token': control_token, 'state': state}, timeout=3)
        except KaliNmapProviderError as exc:
            last_error = exc
            if 'execution_ref is not active' not in str(exc) or attempt == 19:
                raise
            time.sleep(0.05)
            continue
        if result.get('status') != 'ok' or result.get('state') != state:
            raise KaliNmapProviderError(f'Kali network provider did not enter requested state {state!r}')
        return
    if last_error is not None:
        raise last_error


def execute_kali_nmap(
    *,
    target: str,
    timeout_seconds: int,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
    poll_interval: float = 1.0,
) -> dict[str, Any]:
    for name, value in (('execution_ref', execution_ref), ('authorization_ref', authorization_ref), ('scope_ref', scope_ref)):
        if not value or len(value) > 255:
            raise KaliNmapProviderError(f'{name} is required for Kali Nmap execution')

    expected = _trusted_expected_provenance()
    _preflight_runtime_attestation(expected)
    control_token = secrets.token_hex(32)
    request_payload = {
        'schema_version': 1,
        'execution_ref': execution_ref,
        'authorization_ref': authorization_ref,
        'scope_ref': scope_ref,
        'control_token': control_token,
        'capability_id': 'network.nmap',
        'target': target,
        'options': {},
        'timeout_seconds': int(timeout_seconds),
    }
    holder: dict[str, Any] = {}

    def invoke() -> None:
        try:
            holder['result'] = _request_json('POST', '/v1/execute', request_payload, timeout=float(timeout_seconds + 15))
        except BaseException as exc:
            holder['error'] = exc

    thread = threading.Thread(target=invoke, name=f'kali-nmap-{execution_ref[:32]}', daemon=True)
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
            raise KaliNmapProviderError(f'Kali network provider control failed: {control_error}') from control_error
        if cancelled:
            thread.join(timeout=10)
            raise KaliNmapProviderCancelled('Kali Nmap capability execution cancelled')
        thread.join(timeout=1)
        if thread.is_alive():
            try:
                _control(execution_ref, control_token, 'cancelled')
            except BaseException:
                pass
            raise KaliNmapProviderError('Kali network provider request did not terminate cleanly')
        if 'error' in holder:
            error = holder['error']
            if isinstance(error, BaseException):
                raise error
            raise KaliNmapProviderError('Kali network provider request failed')
        result = holder.get('result')
        if not isinstance(result, dict) or result.get('status') != 'completed':
            raise KaliNmapProviderError('Kali network provider returned an incomplete execution result')
        if result.get('capability_id') != 'network.nmap' or result.get('tool') != 'nmap':
            raise KaliNmapProviderError('Kali network provider response binding mismatch')
        if result.get('target') != target:
            raise KaliNmapProviderError('Kali network provider response target mismatch')
        if not isinstance(result.get('exit_code'), int):
            raise KaliNmapProviderError('Kali network provider exit_code is missing or invalid')
        for field in ('stdout', 'stderr'):
            if not isinstance(result.get(field), str):
                raise KaliNmapProviderError(f'Kali network provider {field} is missing or invalid')
        result = dict(result)
        result['runtime'] = _validate_runtime(result.get('runtime'), expected, top_level_tool=result.get('tool'))
        return result
    finally:
        if thread.is_alive():
            try:
                _control(execution_ref, control_token, 'cancelled')
            except BaseException:
                pass
