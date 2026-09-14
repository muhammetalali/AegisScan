from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import ssl
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import native_output_normalizer, native_tool_runtime
from .native_tool_runtime import NativeToolSpec
from .pinned_http import PinnedHTTPResponse, pinned_http_operation, request_pinned
from .scanner_adapters import ScanResult, validate_authorized_web_target

_INTERNAL_IDS = {
    'web.http-method-policy',
    'web.duplicate-parameter-semantics',
    'web.ssrf-canary-validation',
    'tls.posture',
}

_WSTG_IDS = {
    'web.http-method-policy': 'WSTG-CONF-06',
    'web.duplicate-parameter-semantics': 'WSTG-INPV-04',
    'web.ssrf-canary-validation': 'WSTG-INPV-19',
    'tls.posture': 'WSTG-CRYP-01',
}

_SPECS = {
    'web.http-method-policy': NativeToolSpec(
        'web.http-method-policy', 'aegis-internal-wstg', 'web-protocol-security',
        'Bounded HTTP method-policy observation using GET, HEAD and OPTIONS only.',
        'url', ('website', 'api_endpoint'), 'active-low', 'url', None, timeout=90,
    ),
    'web.duplicate-parameter-semantics': NativeToolSpec(
        'web.duplicate-parameter-semantics', 'aegis-internal-wstg', 'web-input-validation',
        'Deterministic duplicate-parameter response-semantics observation using a synthetic inert query key.',
        'url', ('website', 'api_endpoint'), 'active-low', 'url', None, timeout=90,
    ),
    'web.ssrf-canary-validation': NativeToolSpec(
        'web.ssrf-canary-validation', 'aegis-internal-wstg', 'web-input-validation',
        'Governed SSRF validation gate that abstains unless a first-class Aegis OAST/canary contract exists.',
        'url', ('website', 'api_endpoint'), 'active-low', 'url', None, timeout=60,
    ),
    'tls.posture': NativeToolSpec(
        'tls.posture', 'aegis-internal-wstg', 'transport-security',
        'Authorization-pinned TLS negotiation and certificate posture observation for HTTPS assets.',
        'url', ('website', 'api_endpoint'), 'active-low', 'url', None, timeout=90,
    ),
}

_ORIGINAL_RUN = native_tool_runtime.run_native_tool
_ORIGINAL_NORMALIZE = native_output_normalizer.normalize_native_output
_INSTALLED = False


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


def _method_policy(target: str) -> dict[str, Any]:
    options = request_pinned('OPTIONS', target, timeout=10, max_body_bytes=4096)
    head = request_pinned('HEAD', target, timeout=10, max_body_bytes=0)
    get = request_pinned('GET', target, timeout=10, max_body_bytes=8192)
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


def _hpp_url(target: str, values: tuple[str, str]) -> str:
    parsed = urlsplit(target)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend((('aegis_hpp_probe', values[0]), ('aegis_hpp_probe', values[1])))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', urlencode(query, doseq=True), parsed.fragment))


def _duplicate_parameter_semantics(target: str) -> dict[str, Any]:
    baseline = request_pinned('GET', target, timeout=10, max_body_bytes=16384)
    first = request_pinned('GET', _hpp_url(target, ('1', '2')), timeout=10, max_body_bytes=16384)
    reverse = request_pinned('GET', _hpp_url(target, ('2', '1')), timeout=10, max_body_bytes=16384)
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


def _ssrf_canary_validation(target: str) -> dict[str, Any]:
    del target
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


def _tls_posture(target: str, destination) -> dict[str, Any]:
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


def _run_internal(
    capability_id: str,
    target: str,
    options: dict[str, Any],
    state_getter=None,
    poll_interval: float = 0.5,
    credential_materials: tuple[Mapping[str, Any], ...] | None = None,
) -> ScanResult:
    del poll_interval
    spec = _SPECS[capability_id]
    if options:
        raise ValueError(f'{capability_id} does not accept runtime options')
    if credential_materials:
        raise ValueError(f'{capability_id} does not accept credential material')
    if state_getter is not None and state_getter() == 'cancelled':
        raise native_tool_runtime.NativeExecutionCancelled('Native capability execution cancelled')
    canonical = validate_authorized_web_target(target)
    with pinned_http_operation(canonical) as destination:
        if capability_id == 'web.http-method-policy':
            observation = _method_policy(canonical)
        elif capability_id == 'web.duplicate-parameter-semantics':
            observation = _duplicate_parameter_semantics(canonical)
        elif capability_id == 'web.ssrf-canary-validation':
            observation = _ssrf_canary_validation(canonical)
        else:
            observation = _tls_posture(canonical, destination)
    payload = {
        'schema': 'aegis.wstg-native-observations.v1',
        'observations': [observation],
    }
    return ScanResult(
        tool=spec.binary,
        target=canonical,
        exit_code=0,
        stdout=json.dumps(payload, sort_keys=True, separators=(',', ':')),
        stderr='',
    )


def _run_dispatch(
    capability_id: str,
    target: str,
    options: dict[str, Any],
    state_getter=None,
    poll_interval: float = 0.5,
    credential_materials: tuple[Mapping[str, Any], ...] | None = None,
) -> ScanResult:
    if capability_id in _INTERNAL_IDS:
        return _run_internal(
            capability_id,
            target,
            options,
            state_getter=state_getter,
            poll_interval=poll_interval,
            credential_materials=credential_materials,
        )
    return _ORIGINAL_RUN(
        capability_id,
        target,
        options,
        state_getter=state_getter,
        poll_interval=poll_interval,
        credential_materials=credential_materials,
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


def _normalize_dispatch(capability_id: str, raw: str) -> dict[str, Any]:
    if capability_id not in _INTERNAL_IDS:
        return _ORIGINAL_NORMALIZE(capability_id, raw)
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
            safe = _safe_value(row)
            if isinstance(safe, dict):
                safe['capability_id'] = capability_id
                safe['wstg_id'] = _WSTG_IDS[capability_id]
                safe['observation_only'] = True
                safe['final_decision'] = False
                observations.append(safe)
    return {
        'schema': 'aegis.native-observations.v1',
        'count': len(observations),
        'observations': observations,
    }


def register_wstg_native_capabilities() -> None:
    global _INSTALLED
    if _INSTALLED:
        return
    for capability_id, spec in _SPECS.items():
        existing = native_tool_runtime.NATIVE_TOOL_SPECS.get(capability_id)
        if existing is not None and existing != spec:
            raise RuntimeError(f'Conflicting WSTG native capability registration: {capability_id}')
        native_tool_runtime.NATIVE_TOOL_SPECS[capability_id] = spec
    native_tool_runtime.run_native_tool = _run_dispatch
    native_output_normalizer.normalize_native_output = _normalize_dispatch
    _INSTALLED = True
