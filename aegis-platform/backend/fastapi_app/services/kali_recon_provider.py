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
_RECON_TOOL_BY_CAPABILITY = {
    'recon.amass': 'amass',
    'recon.subfinder': 'subfinder',
    'recon.dnsenum': 'dnsenum',
    'recon.fierce': 'fierce',
}
_RECON_CAPABILITIES = frozenset(_RECON_TOOL_BY_CAPABILITY)

_ROUTING_SCHEMA = 'aegis.recon-provider-routing.v1'
_CANARY_BUCKET_COUNT = 10_000
_MAX_CANARY_BPS = 2_500
_CANARY_PARITY_APPROVED_CAPABILITIES = frozenset({'recon.fierce'})


@dataclass(frozen=True)
class ReconProviderDecision:
    schema: str
    mode: str
    capability_id: str
    selected_provider: str
    recon_capability: bool
    parity_approved: bool
    canary_bps: int
    bucket: int | None
    routing_key_digest: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)



class KaliReconProviderError(RuntimeError):
    pass


class KaliReconProviderCancelled(KaliReconProviderError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def provider_mode() -> str:
    mode = os.getenv('AEGIS_RECON_PROVIDER', 'legacy').strip().lower()
    if mode not in {'legacy', 'canary', 'kali'}:
        raise KaliReconProviderError('AEGIS_RECON_PROVIDER must be legacy, canary, or kali')
    return mode


def _canary_bps() -> int:
    raw = os.getenv('AEGIS_KALI_RECON_CANARY_BPS', '0').strip()
    if not re.fullmatch(r'\d{1,5}', raw):
        raise KaliReconProviderError('AEGIS_KALI_RECON_CANARY_BPS must be an integer from 0 to 2500')
    value = int(raw)
    if value < 0 or value > _MAX_CANARY_BPS:
        raise KaliReconProviderError('AEGIS_KALI_RECON_CANARY_BPS must be an integer from 0 to 2500')
    return value


def _routing_key_digest(capability_id: str, routing_key: str) -> tuple[str, int]:
    normalized = str(routing_key or '').strip()
    if not normalized or len(normalized) > 255:
        raise KaliReconProviderError('A non-empty routing_key of at most 255 characters is required for active canary routing')
    material = f'{_ROUTING_SCHEMA}\x00{capability_id}\x00{normalized}'.encode('utf-8')
    digest = hashlib.sha256(material).hexdigest()
    bucket = int(digest[:16], 16) % _CANARY_BUCKET_COUNT
    return digest, bucket


def recon_provider_decision(capability_id: str, *, routing_key: str | None = None) -> ReconProviderDecision:
    capability = str(capability_id or '').strip()
    mode = provider_mode()
    recon_capability = capability in _RECON_CAPABILITIES
    parity_approved = capability in _CANARY_PARITY_APPROVED_CAPABILITIES

    if not recon_capability:
        return ReconProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id=capability,
            selected_provider='legacy',
            recon_capability=False,
            parity_approved=False,
            canary_bps=0,
            bucket=None,
            routing_key_digest='',
            reason='capability-not-kali-recon',
        )

    if mode == 'legacy':
        return ReconProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id=capability,
            selected_provider='legacy',
            recon_capability=True,
            parity_approved=parity_approved,
            canary_bps=0,
            bucket=None,
            routing_key_digest='',
            reason='legacy-default',
        )

    if mode == 'kali':
        return ReconProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id=capability,
            selected_provider='kali',
            recon_capability=True,
            parity_approved=parity_approved,
            canary_bps=_CANARY_BUCKET_COUNT,
            bucket=None,
            routing_key_digest='',
            reason='explicit-kali-mode',
        )

    canary_bps = _canary_bps()
    if not parity_approved:
        return ReconProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id=capability,
            selected_provider='legacy',
            recon_capability=True,
            parity_approved=False,
            canary_bps=canary_bps,
            bucket=None,
            routing_key_digest='',
            reason='capability-not-parity-approved',
        )
    if canary_bps == 0:
        return ReconProviderDecision(
            schema=_ROUTING_SCHEMA,
            mode=mode,
            capability_id=capability,
            selected_provider='legacy',
            recon_capability=True,
            parity_approved=True,
            canary_bps=0,
            bucket=None,
            routing_key_digest='',
            reason='canary-rollback-zero',
        )

    digest, bucket = _routing_key_digest(capability, routing_key or '')
    selected = bucket < canary_bps
    return ReconProviderDecision(
        schema=_ROUTING_SCHEMA,
        mode=mode,
        capability_id=capability,
        selected_provider='kali' if selected else 'legacy',
        recon_capability=True,
        parity_approved=True,
        canary_bps=canary_bps,
        bucket=bucket,
        routing_key_digest=digest,
        reason='canary-selected' if selected else 'canary-holdback',
    )


def should_use_kali_recon(capability_id: str, *, routing_key: str | None = None) -> bool:
    return recon_provider_decision(capability_id, routing_key=routing_key).selected_provider == 'kali'


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


def _required_expected(name: str, validator: re.Pattern[str] | None = None) -> str:
    value = os.getenv(name, '').strip()
    if not value:
        raise KaliReconProviderError(f'{name} is required when AEGIS_RECON_PROVIDER=kali')
    if validator is not None and not validator.fullmatch(value):
        raise KaliReconProviderError(f'{name} is invalid')
    if validator is None and not _RUNTIME_TEXT_RE.fullmatch(value):
        raise KaliReconProviderError(f'{name} is invalid')
    return value


def _trusted_expected_provenance() -> dict[str, str]:
    return {
        'runner_version': _required_expected('AEGIS_KALI_RECON_EXPECTED_RUNNER_VERSION'),
        'build_commit': _required_expected('AEGIS_KALI_RECON_EXPECTED_BUILD_COMMIT', _COMMIT_RE),
        'base_image_digest': _required_expected('AEGIS_KALI_RECON_EXPECTED_BASE_IMAGE_DIGEST', _SHA256_RE),
        'tool_manifest_digest': _required_expected('AEGIS_KALI_RECON_EXPECTED_TOOL_MANIFEST_DIGEST', _SHA256_RE),
        'image_digest': _required_expected('AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST', _SHA256_RE),
        'runtime_manifest_digest': _required_expected(
            'AEGIS_KALI_RECON_EXPECTED_RUNTIME_MANIFEST_DIGEST', _SHA256_RE
        ),
    }


def _validate_runtime_provenance(
    *,
    capability_id: str,
    top_level_tool: Any,
    runtime: Any,
    expected: dict[str, str],
) -> dict[str, Any]:
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
        'runtime_manifest_digest': runtime.get('runtime_manifest_digest'),
    }
    _bounded_runtime_text('tool_version', runtime.get('tool_version'))
    _bounded_runtime_text('tool_source', runtime.get('tool_source'))

    if not isinstance(actual['build_commit'], str) or not _COMMIT_RE.fullmatch(actual['build_commit']):
        raise KaliReconProviderError('Kali recon provider runtime build_commit is missing or invalid')
    for field in ('base_image_digest', 'tool_manifest_digest', 'runtime_manifest_digest'):
        value = actual[field]
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise KaliReconProviderError(f'Kali recon provider runtime {field} is missing or invalid')

    for field in (
        'runner_version',
        'build_commit',
        'base_image_digest',
        'tool_manifest_digest',
        'runtime_manifest_digest',
    ):
        if actual[field] != expected[field]:
            raise KaliReconProviderError(f'Kali recon provider pinned {field} mismatch')

    trusted_runtime = dict(runtime)
    # The execution image identity is owned by deployment/Control Plane authority.
    # The provider cannot prove its own container image digest without a privileged
    # runtime API, so never accept a provider-supplied value as authority.
    trusted_runtime['image_digest'] = expected['image_digest']
    trusted_runtime['runtime_manifest_digest'] = expected['runtime_manifest_digest']
    trusted_runtime['provenance_authority'] = 'control-plane-deployment-pins'
    return trusted_runtime


def _request_json(method: str, path: str, payload: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    normalized_method = str(method or '').strip().upper()
    body = None
    headers = {
        'Accept': 'application/json',
        'X-Aegis-Recon-Token': _auth_token(),
    }
    if normalized_method != 'GET':
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(
        _base_url() + path,
        data=body,
        method=normalized_method,
        headers=headers,
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


def _validate_runtime_attestation(payload: Any, expected: dict[str, str]) -> None:
    if not isinstance(payload, dict) or payload.get('status') != 'ok':
        raise KaliReconProviderError('Kali recon provider runtime attestation is missing or invalid')
    runtime = payload.get('runtime')
    if not isinstance(runtime, dict):
        raise KaliReconProviderError('Kali recon provider runtime attestation is missing or invalid')
    if runtime.get('provider') != 'aegis-kali-recon':
        raise KaliReconProviderError('Kali recon provider attested provider is invalid')
    if runtime.get('profile') != 'recon':
        raise KaliReconProviderError('Kali recon provider attested profile mismatch')

    actual = {
        'runner_version': _bounded_runtime_text('runner_version', runtime.get('runner_version')),
        'build_commit': runtime.get('build_commit'),
        'base_image_digest': runtime.get('base_image_digest'),
        'tool_manifest_digest': runtime.get('tool_manifest_digest'),
        'runtime_manifest_digest': runtime.get('runtime_manifest_digest'),
    }
    if not isinstance(actual['build_commit'], str) or not _COMMIT_RE.fullmatch(actual['build_commit']):
        raise KaliReconProviderError('Kali recon provider attested build_commit is missing or invalid')
    for field in ('base_image_digest', 'tool_manifest_digest', 'runtime_manifest_digest'):
        value = actual[field]
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise KaliReconProviderError(f'Kali recon provider attested {field} is missing or invalid')
    for field in (
        'runner_version',
        'build_commit',
        'base_image_digest',
        'tool_manifest_digest',
        'runtime_manifest_digest',
    ):
        if actual[field] != expected[field]:
            raise KaliReconProviderError(f'Kali recon provider pinned {field} mismatch')


def _preflight_runtime_attestation(expected: dict[str, str]) -> None:
    attestation = _request_json('GET', '/v1/runtime', {}, timeout=5)
    _validate_runtime_attestation(attestation, expected)


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

    # Resolve the complete Control Plane trust anchor before any request leaves
    # the worker. Kali mode is therefore fail-closed if deployment provenance is
    # incomplete or malformed.
    expected_provenance = _trusted_expected_provenance()
    # Authenticate and bind the provider runtime before any scanner binary is
    # launched. A drifted deployment pin therefore fails closed at the trust
    # boundary instead of after a potentially long external execution.
    _preflight_runtime_attestation(expected_provenance)

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
        result['runtime'] = _validate_runtime_provenance(
            capability_id=capability_id,
            top_level_tool=result.get('tool'),
            runtime=result.get('runtime'),
            expected=expected_provenance,
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
