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

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_AUTH_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_SHA256_RE = re.compile(r'^sha256:[a-f0-9]{64}$')
_COMMIT_RE = re.compile(r'^[a-f0-9]{40}$')
_RUNTIME_TEXT_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,254}$')
_ROUTING_SCHEMA = 'aegis.masscan-provider-routing.v1'
_CANARY_BUCKET_COUNT = 10_000
_MAX_CANARY_BPS = 2_500


@dataclass(frozen=True)
class MasscanProviderDecision:
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


class KaliMasscanProviderError(RuntimeError):
    pass


class KaliMasscanProviderCancelled(KaliMasscanProviderError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def provider_mode() -> str:
    mode = os.getenv('AEGIS_MASSCAN_PROVIDER', 'legacy').strip().lower()
    if mode not in {'legacy', 'canary', 'default-kali', 'kali'}:
        raise KaliMasscanProviderError(
            'AEGIS_MASSCAN_PROVIDER must be legacy, canary, default-kali, or kali'
        )
    return mode


def _canary_bps() -> int:
    raw = os.getenv('AEGIS_KALI_MASSCAN_CANARY_BPS', '0').strip()
    if not re.fullmatch(r'\d{1,5}', raw):
        raise KaliMasscanProviderError('AEGIS_KALI_MASSCAN_CANARY_BPS must be an integer from 0 to 2500')
    value = int(raw)
    if value > _MAX_CANARY_BPS:
        raise KaliMasscanProviderError('AEGIS_KALI_MASSCAN_CANARY_BPS must be an integer from 0 to 2500')
    return value


def _routing_key_digest(routing_key: str) -> tuple[str, int]:
    normalized = str(routing_key or '').strip()
    if not normalized or len(normalized) > 255:
        raise KaliMasscanProviderError('A non-empty routing_key of at most 255 characters is required for Masscan canary routing')
    material = f'{_ROUTING_SCHEMA}\x00network.masscan\x00{normalized}'.encode('utf-8')
    digest = hashlib.sha256(material).hexdigest()
    return digest, int(digest[:16], 16) % _CANARY_BUCKET_COUNT


def masscan_provider_decision(*, routing_key: str | None = None) -> MasscanProviderDecision:
    mode = provider_mode()
    if mode == 'legacy':
        return MasscanProviderDecision(
            schema=_ROUTING_SCHEMA, mode=mode, capability_id='network.masscan',
            selected_provider='legacy', parity_approved=True, canary_bps=0,
            bucket=None, routing_key_digest='', reason='legacy-default',
        )
    if mode == 'default-kali':
        return MasscanProviderDecision(
            schema=_ROUTING_SCHEMA, mode=mode, capability_id='network.masscan',
            selected_provider='kali', parity_approved=True, canary_bps=0,
            bucket=None, routing_key_digest='', reason='default-kali-parity-approved',
        )
    if mode == 'kali':
        return MasscanProviderDecision(
            schema=_ROUTING_SCHEMA, mode=mode, capability_id='network.masscan',
            selected_provider='kali', parity_approved=True, canary_bps=_CANARY_BUCKET_COUNT,
            bucket=None, routing_key_digest='', reason='explicit-kali-mode',
        )
    canary_bps = _canary_bps()
    if canary_bps == 0:
        return MasscanProviderDecision(
            schema=_ROUTING_SCHEMA, mode=mode, capability_id='network.masscan',
            selected_provider='legacy', parity_approved=True, canary_bps=0,
            bucket=None, routing_key_digest='', reason='canary-rollback-zero',
        )
    digest, bucket = _routing_key_digest(routing_key or '')
    selected = bucket < canary_bps
    return MasscanProviderDecision(
        schema=_ROUTING_SCHEMA, mode=mode, capability_id='network.masscan',
        selected_provider='kali' if selected else 'legacy', parity_approved=True,
        canary_bps=canary_bps, bucket=bucket, routing_key_digest=digest,
        reason='canary-selected' if selected else 'canary-holdback',
    )


def _auth_token() -> str:
    token = os.getenv('AEGIS_KALI_MASSCAN_AUTH_TOKEN', '').strip()
    if not _AUTH_TOKEN_RE.fullmatch(token):
        raise KaliMasscanProviderError('AEGIS_KALI_MASSCAN_AUTH_TOKEN must be a 64-character lowercase hex token')
    return token


def _base_url() -> str:
    raw = os.getenv('AEGIS_KALI_MASSCAN_URL', 'http://127.0.0.1:18767').strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1':
        raise KaliMasscanProviderError('AEGIS_KALI_MASSCAN_URL must be an http 127.0.0.1 endpoint')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'', '/'}:
        raise KaliMasscanProviderError('AEGIS_KALI_MASSCAN_URL must not contain credentials, path, query, or fragment')
    port = parsed.port or 80
    if port < 1024 or port > 65535:
        raise KaliMasscanProviderError('AEGIS_KALI_MASSCAN_URL port must be between 1024 and 65535')
    return f'http://127.0.0.1:{port}'


def _direct_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _required_expected(name: str, validator: re.Pattern[str] | None = None) -> str:
    value = os.getenv(name, '').strip()
    if not value:
        raise KaliMasscanProviderError(f'{name} is required when governed Kali Masscan execution is active')
    if validator is not None and not validator.fullmatch(value):
        raise KaliMasscanProviderError(f'{name} is invalid')
    if validator is None and not _RUNTIME_TEXT_RE.fullmatch(value):
        raise KaliMasscanProviderError(f'{name} is invalid')
    return value


def _trusted_expected_provenance() -> dict[str, str]:
    return {
        'runner_version': _required_expected('AEGIS_KALI_MASSCAN_EXPECTED_RUNNER_VERSION'),
        'build_commit': _required_expected('AEGIS_KALI_MASSCAN_EXPECTED_BUILD_COMMIT', _COMMIT_RE),
        'base_image_digest': _required_expected('AEGIS_KALI_MASSCAN_EXPECTED_BASE_IMAGE_DIGEST', _SHA256_RE),
        'tool_manifest_digest': _required_expected('AEGIS_KALI_MASSCAN_EXPECTED_TOOL_MANIFEST_DIGEST', _SHA256_RE),
        'image_digest': _required_expected('AEGIS_KALI_MASSCAN_EXPECTED_IMAGE_DIGEST', _SHA256_RE),
        'runtime_manifest_digest': _required_expected('AEGIS_KALI_MASSCAN_EXPECTED_RUNTIME_MANIFEST_DIGEST', _SHA256_RE),
    }


def _request_json(method: str, path: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    body = None
    headers = {'Accept': 'application/json', 'X-Aegis-Masscan-Token': _auth_token()}
    if method != 'GET':
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(_base_url() + path, data=body, method=method, headers=headers)
    try:
        with _direct_opener().open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = exc.read(8192).decode('utf-8', errors='replace').strip()
        raise KaliMasscanProviderError(f'Kali Masscan provider rejected request ({exc.code}): {detail[:2000]}') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise KaliMasscanProviderError(f'Kali Masscan provider is unavailable: {exc}') from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise KaliMasscanProviderError('Kali Masscan provider response exceeded 8 MiB')
    try:
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KaliMasscanProviderError('Kali Masscan provider returned invalid JSON') from exc
    if not isinstance(result, dict):
        raise KaliMasscanProviderError('Kali Masscan provider response must be a JSON object')
    return result


def _validate_runtime(runtime: Any, expected: dict[str, str], *, top_level_tool: Any | None = None) -> dict[str, Any]:
    if not isinstance(runtime, dict):
        raise KaliMasscanProviderError('Kali Masscan runtime attestation is missing')
    if runtime.get('provider') != 'aegis-kali-network-masscan':
        raise KaliMasscanProviderError('Kali Masscan provider identity mismatch')
    if runtime.get('profile') != 'network':
        raise KaliMasscanProviderError('Kali Masscan profile mismatch')
    if runtime.get('dispatch_state') != 'semantic-masscan-provider':
        raise KaliMasscanProviderError('Kali Masscan dispatch state mismatch')
    if runtime.get('dispatch_capabilities') != ['network.masscan']:
        raise KaliMasscanProviderError('Kali Masscan capability boundary mismatch')
    if top_level_tool is not None and top_level_tool != 'masscan':
        raise KaliMasscanProviderError('Kali Masscan tool binding mismatch')
    if runtime.get('tool') not in {None, 'masscan'}:
        raise KaliMasscanProviderError('Kali Masscan runtime tool mismatch')
    if runtime.get('tool_version') not in {None, '2:1.3.2+ds1-2'}:
        raise KaliMasscanProviderError('Kali Masscan tool version mismatch')

    actual = {
        'runner_version': runtime.get('runner_version'),
        'build_commit': runtime.get('build_commit'),
        'base_image_digest': runtime.get('base_image_digest'),
        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
        'runtime_manifest_digest': runtime.get('runtime_manifest_digest'),
    }
    if not isinstance(actual['runner_version'], str) or not _RUNTIME_TEXT_RE.fullmatch(actual['runner_version']):
        raise KaliMasscanProviderError('Kali Masscan runner_version is missing or invalid')
    if not isinstance(actual['build_commit'], str) or not _COMMIT_RE.fullmatch(actual['build_commit']):
        raise KaliMasscanProviderError('Kali Masscan build_commit is missing or invalid')
    for field in ('base_image_digest', 'tool_manifest_digest', 'runtime_manifest_digest'):
        value = actual[field]
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise KaliMasscanProviderError(f'Kali Masscan {field} is missing or invalid')
    for field in ('runner_version', 'build_commit', 'base_image_digest', 'tool_manifest_digest', 'runtime_manifest_digest'):
        if actual[field] != expected[field]:
            raise KaliMasscanProviderError(f'Kali Masscan pinned {field} mismatch')

    privilege = runtime.get('linux_privilege')
    if not isinstance(privilege, dict):
        raise KaliMasscanProviderError('Kali Masscan Linux privilege attestation is missing')
    for name in ('effective', 'permitted', 'bounding'):
        if privilege.get(name) != '0000000000002000':
            raise KaliMasscanProviderError(f'Kali Masscan {name} must contain exactly CAP_NET_RAW')
    if privilege.get('no_new_privs') is not True or privilege.get('allowed_capabilities') != ['CAP_NET_RAW']:
        raise KaliMasscanProviderError('Kali Masscan privilege boundary mismatch')

    trusted = dict(runtime)
    trusted['image_digest'] = expected['image_digest']
    trusted['runtime_manifest_digest'] = expected['runtime_manifest_digest']
    trusted['provenance_authority'] = 'control-plane-deployment-pins'
    return trusted


def _preflight_runtime_attestation(expected: dict[str, str]) -> None:
    payload = _request_json('GET', '/v1/runtime', {}, timeout=5)
    if payload.get('status') != 'ok':
        raise KaliMasscanProviderError('Kali Masscan runtime attestation is missing or invalid')
    _validate_runtime(payload.get('runtime'), expected)


def _control(execution_ref: str, control_token: str, state: str) -> None:
    path = f'/v1/executions/{urllib.parse.quote(execution_ref, safe=":._-")}/control'
    last_error: KaliMasscanProviderError | None = None
    for attempt in range(20):
        try:
            result = _request_json('POST', path, {'control_token': control_token, 'state': state}, timeout=3)
        except KaliMasscanProviderError as exc:
            last_error = exc
            if 'execution_ref is not active' not in str(exc) or attempt == 19:
                raise
            time.sleep(0.05)
            continue
        if result.get('status') != 'ok' or result.get('state') != state:
            raise KaliMasscanProviderError(f'Kali Masscan provider did not enter requested state {state!r}')
        return
    if last_error is not None:
        raise last_error


def execute_kali_masscan(
    *,
    target: str,
    ports: str,
    rate: int,
    timeout_seconds: int,
    execution_ref: str,
    authorization_ref: str,
    scope_ref: str,
    state_getter: Callable[[], str] | None,
    interface: str | None = None,
    adapter_ip: str | None = None,
    adapter_mac: str | None = None,
    router_mac: str | None = None,
    poll_interval: float = 1.0,
) -> dict[str, Any]:
    for name, value in (('execution_ref', execution_ref), ('authorization_ref', authorization_ref), ('scope_ref', scope_ref)):
        if not value or len(value) > 255:
            raise KaliMasscanProviderError(f'{name} is required for Kali Masscan execution')

    expected = _trusted_expected_provenance()
    _preflight_runtime_attestation(expected)
    control_token = secrets.token_hex(32)
    request_payload = {
        'schema_version': 1,
        'execution_ref': execution_ref,
        'authorization_ref': authorization_ref,
        'scope_ref': scope_ref,
        'control_token': control_token,
        'capability_id': 'network.masscan',
        'target': target,
        'options': {
            'ports': ports,
            'rate': int(rate),
            'interface': interface,
            'adapter_ip': adapter_ip,
            'adapter_mac': adapter_mac,
            'router_mac': router_mac,
        },
        'timeout_seconds': int(timeout_seconds),
    }
    holder: dict[str, Any] = {}

    def invoke() -> None:
        try:
            holder['result'] = _request_json('POST', '/v1/execute', request_payload, timeout=float(timeout_seconds + 15))
        except BaseException as exc:
            holder['error'] = exc

    thread = threading.Thread(target=invoke, name=f'kali-masscan-{execution_ref[:32]}', daemon=True)
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
            raise KaliMasscanProviderError(f'Kali Masscan provider control failed closed: {control_error}') from control_error
        if cancelled:
            thread.join(timeout=10)
            raise KaliMasscanProviderCancelled('Kali Masscan execution cancelled')
        thread.join(timeout=1)
        if thread.is_alive():
            try:
                _control(execution_ref, control_token, 'cancelled')
            except BaseException:
                pass
            raise KaliMasscanProviderError('Kali Masscan provider request did not terminate cleanly')
        if 'error' in holder:
            error = holder['error']
            if isinstance(error, BaseException):
                raise error
            raise KaliMasscanProviderError('Kali Masscan provider request failed')

        result = holder.get('result')
        if not isinstance(result, dict) or result.get('status') != 'completed':
            raise KaliMasscanProviderError('Kali Masscan provider returned an incomplete execution result')
        if result.get('capability_id') != 'network.masscan' or result.get('tool') != 'masscan':
            raise KaliMasscanProviderError('Kali Masscan provider response binding mismatch')
        if result.get('target') != target:
            raise KaliMasscanProviderError('Kali Masscan provider response target mismatch')
        if result.get('options') != request_payload['options']:
            raise KaliMasscanProviderError('Kali Masscan provider response options mismatch')
        if not isinstance(result.get('exit_code'), int):
            raise KaliMasscanProviderError('Kali Masscan provider exit_code is missing or invalid')
        for field in ('stdout', 'stderr'):
            if not isinstance(result.get(field), str):
                raise KaliMasscanProviderError(f'Kali Masscan provider {field} is missing or invalid')
        trusted_result = dict(result)
        trusted_result['runtime'] = _validate_runtime(
            result.get('runtime'), expected, top_level_tool=result.get('tool')
        )
        return trusted_result
    finally:
        if thread.is_alive():
            try:
                _control(execution_ref, control_token, 'cancelled')
            except BaseException:
                pass
