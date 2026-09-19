from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import socket
import ssl
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlencode, urlsplit, urlunsplit

from .native_tool_runtime import NativeExecutionCancelled
from .pinned_http import PinnedHTTPResponse, pinned_http_operation, request_pinned
from .scanner_adapters import ScanResult, validate_authorized_web_target


@dataclass(frozen=True)
class WSTGInternalSpec:
    capability_id: str
    tool: str
    category: str
    description: str
    scan_type: str
    asset_types: tuple[str, ...]
    risk: str
    timeout: int
    credential_mode: str = 'none'
    credential_kinds: tuple[str, ...] = ()
    credential_required: bool = False

    @property
    def allowed_options(self) -> tuple[str, ...]:
        return ()


WSTG_INTERNAL_SPECS: dict[str, WSTGInternalSpec] = {
    'web.http-method-policy': WSTGInternalSpec(
        capability_id='web.http-method-policy',
        tool='aegis-internal-wstg',
        category='web-protocol-security',
        description='Bounded HTTP method-policy observation using GET, HEAD and OPTIONS only.',
        scan_type='url',
        asset_types=('website', 'api_endpoint'),
        risk='active-low',
        timeout=90,
    ),
    'web.duplicate-parameter-semantics': WSTGInternalSpec(
        capability_id='web.duplicate-parameter-semantics',
        tool='aegis-internal-wstg',
        category='web-input-validation',
        description=(
            'Deterministic duplicate-parameter response-semantics observation using a synthetic inert query key.'
        ),
        scan_type='url',
        asset_types=('website', 'api_endpoint'),
        risk='active-low',
        timeout=90,
    ),
    'web.ssrf-canary-validation': WSTGInternalSpec(
        capability_id='web.ssrf-canary-validation',
        tool='aegis-internal-wstg',
        category='web-input-validation',
        description=(
            'Governed SSRF validation gate that abstains unless a first-class Aegis OAST/canary contract exists.'
        ),
        scan_type='url',
        asset_types=('website', 'api_endpoint'),
        risk='active-low',
        timeout=60,
    ),
    'tls.posture': WSTGInternalSpec(
        capability_id='tls.posture',
        tool='aegis-internal-wstg',
        category='transport-security',
        description='Authorization-pinned TLS negotiation and certificate posture observation for HTTPS assets.',
        scan_type='url',
        asset_types=('website', 'api_endpoint'),
        risk='active-low',
        timeout=90,
    ),
}

WSTG_INTERNAL_IDS = frozenset(WSTG_INTERNAL_SPECS)

_WSTG_IDS = {
    'web.http-method-policy': 'WSTG-CONF-06',
    'web.duplicate-parameter-semantics': 'WSTG-INPV-04',
    'web.ssrf-canary-validation': 'WSTG-INPV-19',
    'tls.posture': 'WSTG-CRYP-01',
}

_COMMON_OBSERVATION_FIELDS = frozenset({
    'kind', 'capability_id', 'wstg_id', 'observation_only', 'final_decision', 'abstained',
})
_OBSERVATION_ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    'web.http-method-policy': _COMMON_OBSERVATION_FIELDS | frozenset({
        'statuses', 'allow_methods', 'unsafe_methods_sent',
    }),
    'web.duplicate-parameter-semantics': _COMMON_OBSERVATION_FIELDS | frozenset({
        'synthetic_parameter', 'statuses', 'body_sha256', 'order_sensitive_observed', 'request_method',
    }),
    'web.ssrf-canary-validation': _COMMON_OBSERVATION_FIELDS | frozenset({
        'abstention_reason', 'callback_attempted', 'ssrf_confirmed',
    }),
    'tls.posture': _COMMON_OBSERVATION_FIELDS | frozenset({
        'abstention_reason', 'resolved_ip', 'tls_version', 'cipher', 'cipher_bits',
        'certificate_not_after', 'certificate_hostname_verified',
    }),
}


def is_wstg_internal_capability(capability_id: str) -> bool:
    return capability_id in WSTG_INTERNAL_SPECS


def get_wstg_internal_spec(capability_id: str) -> WSTGInternalSpec:
    try:
        return WSTG_INTERNAL_SPECS[capability_id]
    except KeyError as exc:
        raise ValueError(f'Unknown internal WSTG capability: {capability_id}') from exc


def validate_wstg_internal_options(capability_id: str, options: Mapping[str, Any]) -> dict[str, Any]:
    get_wstg_internal_spec(capability_id)
    if options:
        raise ValueError(f'{capability_id} does not accept runtime options')
    return {}


def _base(capability_id: str) -> dict[str, Any]:
    return {
        'kind': capability_id.replace('.', '_'),
        'capability_id': capability_id,
        'wstg_id': _WSTG_IDS[capability_id],
        'observation_only': True,
        'final_decision': False,
        'abstained': False,
    }


def _status(response: PinnedHTTPResponse) -> int:
    return max(0, min(int(response.status), 599))


def _digest(response: PinnedHTTPResponse) -> str:
    return hashlib.sha256(response.body).hexdigest()


def _method_policy(target: str, checkpoint: Callable[[], None] = lambda: None) -> dict[str, Any]:
    checkpoint()
    options = request_pinned('OPTIONS', target, timeout=10, max_body_bytes=4096)
    checkpoint()
    head = request_pinned('HEAD', target, timeout=10, max_body_bytes=0)
    checkpoint()
    get = request_pinned('GET', target, timeout=10, max_body_bytes=8192)
    checkpoint()
    allow = sorted({
        item.strip().upper()[:16]
        for item in options.headers.get('allow', '').split(',')
        if item.strip() and item.strip().replace('-', '').isalpha()
    })[:32]
    return {
        **_base('web.http-method-policy'),
        'statuses': {'OPTIONS': _status(options), 'HEAD': _status(head), 'GET': _status(get)},
        'allow_methods': allow,
        'unsafe_methods_sent': False,
    }


def _wire_url(target: str) -> str:
    parsed = urlsplit(target)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', parsed.query, ''))


def _hpp_url(target: str, values: tuple[str, str]) -> str:
    parsed = urlsplit(_wire_url(target))
    probe_query = urlencode((
        ('aegis_hpp_probe', values[0]),
        ('aegis_hpp_probe', values[1]),
    ))
    separator = '' if not parsed.query or parsed.query.endswith('&') else '&'
    query = f'{parsed.query}{separator}{probe_query}'
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', query, ''))


def _duplicate_parameter_semantics(
    target: str,
    checkpoint: Callable[[], None] = lambda: None,
) -> dict[str, Any]:
    baseline_target = _wire_url(target)
    checkpoint()
    baseline = request_pinned('GET', baseline_target, timeout=10, max_body_bytes=16384)
    checkpoint()
    first = request_pinned('GET', _hpp_url(baseline_target, ('1', '2')), timeout=10, max_body_bytes=16384)
    checkpoint()
    reverse = request_pinned('GET', _hpp_url(baseline_target, ('2', '1')), timeout=10, max_body_bytes=16384)
    checkpoint()
    return {
        **_base('web.duplicate-parameter-semantics'),
        'synthetic_parameter': 'aegis_hpp_probe',
        'statuses': {
            'BASELINE': _status(baseline),
            'FORWARD': _status(first),
            'REVERSE': _status(reverse),
        },
        'body_sha256': {
            'BASELINE': _digest(baseline),
            'FORWARD': _digest(first),
            'REVERSE': _digest(reverse),
        },
        'order_sensitive_observed': _status(first) != _status(reverse) or _digest(first) != _digest(reverse),
        'request_method': 'GET',
    }


def _ssrf_canary_validation(
    target: str,
    checkpoint: Callable[[], None] = lambda: None,
) -> dict[str, Any]:
    del target
    checkpoint()
    return {
        **_base('web.ssrf-canary-validation'),
        'abstained': True,
        'abstention_reason': (
            'Aegis has no governed first-class OAST/canary callback provider bound to this scan. '
            'SSRF proof is not inferred from reachability and no user-controlled callback URL is contacted.'
        ),
        'callback_attempted': False,
        'ssrf_confirmed': False,
    }


def _sockaddr(raw: str, port: int):
    address = ipaddress.ip_address(raw)
    return (raw, port, 0, 0) if address.version == 6 else (raw, port)


def _tls_posture(
    target: str,
    destination,
    checkpoint: Callable[[], None] = lambda: None,
) -> dict[str, Any]:
    checkpoint()
    parsed = urlsplit(target)
    if parsed.scheme.lower() != 'https':
        return {
            **_base('tls.posture'),
            'abstained': True,
            'abstention_reason': 'TLS posture requires an HTTPS target.',
        }
    context = ssl.create_default_context()
    last_error: Exception | None = None
    for raw_ip in destination.resolved_ips:
        checkpoint()
        raw_socket = socket.socket(
            socket.AF_INET6 if ipaddress.ip_address(raw_ip).version == 6 else socket.AF_INET,
            socket.SOCK_STREAM,
        )
        try:
            raw_socket.settimeout(10)
            raw_socket.connect(_sockaddr(raw_ip, destination.port))
            with context.wrap_socket(raw_socket, server_hostname=destination.host) as tls_socket:
                cipher = tls_socket.cipher() or ('', '', 0)
                cert = tls_socket.getpeercert() or {}
                checkpoint()
                return {
                    **_base('tls.posture'),
                    'resolved_ip': raw_ip,
                    'tls_version': str(tls_socket.version() or '')[:32],
                    'cipher': str(cipher[0] or '')[:128],
                    'cipher_bits': int(cipher[2] or 0),
                    'certificate_not_after': str(cert.get('notAfter') or '')[:128],
                    'certificate_hostname_verified': True,
                }
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            try:
                raw_socket.close()
            except OSError:
                pass
    if last_error is not None:
        raise last_error
    raise RuntimeError('Authorized TLS destination contained no connectable IP address')


def _make_execution_checkpoint(
    spec: WSTGInternalSpec,
    state_getter: Callable[[], str] | None,
    poll_interval: float,
) -> Callable[[], None]:
    interval = max(0.01, min(float(poll_interval), 1.0))
    deadline = time.monotonic() + spec.timeout

    def checkpoint() -> None:
        nonlocal deadline
        while True:
            state = str(state_getter() if state_getter is not None else 'running')
            if state == 'cancelled':
                raise NativeExecutionCancelled('Internal WSTG capability execution cancelled')
            if state != 'paused':
                if time.monotonic() > deadline:
                    raise TimeoutError(
                        f'Internal WSTG capability exceeded timeout={spec.timeout}s'
                    )
                return
            started = time.monotonic()
            time.sleep(interval)
            deadline += time.monotonic() - started

    return checkpoint


def run_wstg_internal_capability(
    capability_id: str,
    target: str,
    options: Mapping[str, Any] | None = None,
    *,
    state_getter: Callable[[], str] | None = None,
    poll_interval: float = 0.5,
    credential_materials: tuple[Mapping[str, Any], ...] | None = None,
) -> ScanResult:
    spec = get_wstg_internal_spec(capability_id)
    validate_wstg_internal_options(capability_id, options or {})
    if credential_materials:
        raise ValueError(f'{capability_id} does not accept credential material')
    checkpoint = _make_execution_checkpoint(spec, state_getter, poll_interval)
    checkpoint()
    canonical = validate_authorized_web_target(target)
    checkpoint()
    with pinned_http_operation(canonical) as destination:
        checkpoint()
        if capability_id == 'web.http-method-policy':
            observation = _method_policy(canonical, checkpoint)
        elif capability_id == 'web.duplicate-parameter-semantics':
            observation = _duplicate_parameter_semantics(canonical, checkpoint)
        elif capability_id == 'web.ssrf-canary-validation':
            observation = _ssrf_canary_validation(canonical, checkpoint)
        else:
            observation = _tls_posture(canonical, destination, checkpoint)
        checkpoint()
    payload = {
        'schema': 'aegis.wstg-native-observations.v1',
        'observations': [observation],
    }
    return ScanResult(
        tool=spec.tool,
        target=canonical,
        exit_code=0,
        stdout=json.dumps(payload, sort_keys=True, separators=(',', ':')),
        stderr='',
    )


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 3:
        return None
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return max(-1_000_000_000, min(value, 1_000_000_000))
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, list):
        return [_safe_value(item, depth=depth + 1) for item in value[:32]]
    if isinstance(value, dict):
        return {
            str(key)[:64]: _safe_value(item, depth=depth + 1)
            for key, item in list(value.items())[:32]
        }
    return str(value)[:512]


def normalize_wstg_internal_output(capability_id: str, raw: str) -> dict[str, Any]:
    get_wstg_internal_spec(capability_id)
    try:
        data = json.loads(raw or '{}')
    except (TypeError, ValueError, json.JSONDecodeError):
        data = {}
    rows = data.get('observations') if isinstance(data, dict) else []
    observations: list[dict[str, Any]] = []
    if isinstance(rows, list):
        for row in rows[:4]:
            if not isinstance(row, dict) or row.get('capability_id') != capability_id:
                continue
            allowed = _OBSERVATION_ALLOWED_FIELDS[capability_id]
            filtered = {key: value for key, value in row.items() if key in allowed}
            safe = _safe_value(filtered)
            if isinstance(safe, dict):
                safe['capability_id'] = capability_id
                safe['wstg_id'] = _WSTG_IDS[capability_id]
                safe['observation_only'] = True
                safe['final_decision'] = False
                safe['abstained'] = bool(safe.get('abstained', False))
                if capability_id == 'web.http-method-policy':
                    safe['unsafe_methods_sent'] = False
                elif capability_id == 'web.ssrf-canary-validation':
                    safe['abstained'] = True
                    safe['callback_attempted'] = False
                    safe['ssrf_confirmed'] = False
                observations.append(safe)
    return {
        'schema': 'aegis.native-observations.v1',
        'count': len(observations),
        'observations': observations,
    }


# Compatibility aliases kept private for the focused validator tests in this PR.
_run_internal = run_wstg_internal_capability
_normalize_dispatch = normalize_wstg_internal_output
