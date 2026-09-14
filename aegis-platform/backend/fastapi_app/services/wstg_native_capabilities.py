from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .pinned_http import PinnedHTTPResponse, pinned_http_operation, request_pinned
from .scanner_adapters import ScanResult, validate_authorized_web_target


@dataclass(frozen=True)
class WSTGNativeSpec:
    capability_id: str
    binary: str
    category: str
    description: str
    scan_type: str
    asset_types: tuple[str, ...]
    risk: str
    timeout: int = 90
    credential_mode: str = 'none'
    credential_kinds: tuple[str, ...] = ()
    credential_required: bool = False
    allowed_options: tuple[str, ...] = ()


WSTG_NATIVE_SPECS: dict[str, WSTGNativeSpec] = {
    'web.http-method-policy': WSTGNativeSpec(
        'web.http-method-policy', 'aegis-wstg-http-method-policy', 'web-protocol-security',
        'Bounded HTTP method policy observation using only GET, HEAD and OPTIONS.',
        'url', ('website', 'api_endpoint'), 'active-low',
    ),
    'web.http-method-override': WSTGNativeSpec(
        'web.http-method-override', 'aegis-wstg-http-method-override', 'web-authorization-security',
        'Non-destructive HTTP method override observation using GET with a HEAD override request.',
        'url', ('website', 'api_endpoint'), 'active-low',
    ),
    'web.websocket-origin-abuse': WSTGNativeSpec(
        'web.websocket-origin-abuse', 'aegis-wstg-websocket-origin', 'web-session-security',
        'Bounded WebSocket origin-handshake observation without sending application frames.',
        'url', ('website',), 'active-low',
    ),
    'web.api-authorization': WSTGNativeSpec(
        'web.api-authorization', 'aegis-wstg-api-authorization', 'api-authorization-security',
        'Anonymous API authorization surface observation that abstains from BOLA classification without identity pairs.',
        'url', ('api_endpoint', 'website'), 'active-low',
    ),
    'web.host-trust-boundaries': WSTGNativeSpec(
        'web.host-trust-boundaries', 'aegis-wstg-host-trust-boundaries', 'web-protocol-security',
        'Bounded Host and forwarded-host trust-boundary observation on the already-authorized pinned destination.',
        'url', ('website', 'api_endpoint'), 'active-low',
    ),
}

_EXPECTED_KINDS = {
    'web.http-method-policy': 'wstg.http_method_policy_case',
    'web.http-method-override': 'wstg.http_method_override_case',
    'web.websocket-origin-abuse': 'wstg.websocket_origin_case',
    'web.api-authorization': 'wstg.api_authorization_case',
    'web.host-trust-boundaries': 'wstg.host_trust_boundary_surface',
}

_WSTG_IDS = {
    'web.http-method-policy': ['WSTG-CONF-06'],
    'web.http-method-override': ['WSTG-ATHZ-09'],
    'web.websocket-origin-abuse': ['WSTG-SESS-13'],
    'web.api-authorization': ['WSTG-ATHZ-04'],
    'web.host-trust-boundaries': ['WSTG-CONF-10'],
}


def is_wstg_native_capability(capability_id: str) -> bool:
    return capability_id in WSTG_NATIVE_SPECS


def get_wstg_native_spec(capability_id: str) -> WSTGNativeSpec:
    try:
        return WSTG_NATIVE_SPECS[capability_id]
    except KeyError as exc:
        raise ValueError(f'Unknown WSTG native capability: {capability_id}') from exc


def validate_wstg_native_options(capability_id: str, options: Mapping[str, Any]) -> dict[str, Any]:
    spec = get_wstg_native_spec(capability_id)
    unknown = sorted(set(options) - set(spec.allowed_options))
    if unknown:
        raise ValueError(f'Unsupported options for {capability_id}: {unknown}')
    return {}


def _status(response: PinnedHTTPResponse) -> int:
    return max(0, min(int(response.status), 599))


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _allow(response: PinnedHTTPResponse) -> list[str]:
    values = response.headers.get('allow', '')
    allowed = {
        item.strip().upper()[:16]
        for item in values.split(',')
        if item.strip() and item.strip().replace('-', '').isalpha()
    }
    return sorted(allowed)[:32]


def _location_authority(response: PinnedHTTPResponse) -> str:
    raw = response.headers.get('location', '').strip()
    if not raw:
        return ''
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ''
    return (parsed.hostname or '').lower().rstrip('.')[:255]


def _request(method: str, target: str, *, headers: Mapping[str, str] | None = None, max_body_bytes: int = 8192) -> PinnedHTTPResponse:
    return request_pinned(
        method,
        target,
        headers=headers,
        timeout=10,
        max_body_bytes=max_body_bytes,
    )


def _base_observation(capability_id: str) -> dict[str, Any]:
    return {
        'kind': _EXPECTED_KINDS[capability_id],
        'capability_id': capability_id,
        'wstg_ids': list(_WSTG_IDS[capability_id]),
        'final_decision': False,
        'observation_only': True,
        'abstained': False,
    }


def _http_method_policy(target: str) -> dict[str, Any]:
    options = _request('OPTIONS', target, max_body_bytes=4096)
    head = _request('HEAD', target, max_body_bytes=0)
    get = _request('GET', target, max_body_bytes=8192)
    return {
        **_base_observation('web.http-method-policy'),
        'statuses': {'OPTIONS': _status(options), 'HEAD': _status(head), 'GET': _status(get)},
        'allow_methods': _allow(options),
        'unsafe_methods_sent': False,
    }


def _http_method_override(target: str) -> dict[str, Any]:
    baseline = _request('GET', target, max_body_bytes=8192)
    overridden = _request(
        'GET', target,
        headers={'X-HTTP-Method-Override': 'HEAD'},
        max_body_bytes=8192,
    )
    return {
        **_base_observation('web.http-method-override'),
        'transport_method': 'GET',
        'override_method': 'HEAD',
        'baseline_status': _status(baseline),
        'override_status': _status(overridden),
        'response_semantics_changed': (
            _status(baseline) != _status(overridden) or _sha256(baseline.body) != _sha256(overridden.body)
        ),
        'unsafe_methods_sent': False,
    }


def _websocket_origin(target: str) -> dict[str, Any]:
    common = {
        'Connection': 'Upgrade',
        'Upgrade': 'websocket',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': 'QUVnaXNTY2FuV1NUR0tleQ==',
    }
    parsed = urlsplit(target)
    trusted_origin = f'{parsed.scheme}://{parsed.netloc}'
    baseline = _request('GET', target, headers={**common, 'Origin': trusted_origin}, max_body_bytes=4096)
    alternate = _request('GET', target, headers={**common, 'Origin': 'https://aegisscan.invalid'}, max_body_bytes=4096)
    return {
        **_base_observation('web.websocket-origin-abuse'),
        'baseline_status': _status(baseline),
        'alternate_origin_status': _status(alternate),
        'baseline_upgrade_accepted': _status(baseline) == 101,
        'alternate_origin_upgrade_accepted': _status(alternate) == 101,
        'application_frames_sent': False,
    }


def _api_authorization(target: str) -> dict[str, Any]:
    response = _request('GET', target, max_body_bytes=8192)
    return {
        **_base_observation('web.api-authorization'),
        'status': _status(response),
        'content_type': response.content_type[:200],
        'anonymous_access_observed': 200 <= _status(response) < 400,
        'abstained': True,
        'abstention_reason': 'Object-level authorization requires at least two bound identity/resource observations; anonymous reachability alone is not a BOLA decision.',
    }


def _host_trust_boundaries(target: str) -> dict[str, Any]:
    baseline = _request('GET', target, max_body_bytes=8192)
    altered = _request(
        'GET', target,
        headers={'Host': 'aegisscan.invalid', 'X-Forwarded-Host': 'aegisscan.invalid'},
        max_body_bytes=8192,
    )
    baseline_location = _location_authority(baseline)
    altered_location = _location_authority(altered)
    return {
        **_base_observation('web.host-trust-boundaries'),
        'baseline_status': _status(baseline),
        'altered_host_status': _status(altered),
        'baseline_redirect_authority': baseline_location,
        'altered_redirect_authority': altered_location,
        'redirect_authority_changed': bool(altered_location and altered_location != baseline_location),
        'network_destination_changed': False,
    }


_PROBES: dict[str, Callable[[str], dict[str, Any]]] = {
    'web.http-method-policy': _http_method_policy,
    'web.http-method-override': _http_method_override,
    'web.websocket-origin-abuse': _websocket_origin,
    'web.api-authorization': _api_authorization,
    'web.host-trust-boundaries': _host_trust_boundaries,
}


def run_wstg_native_probe(capability_id: str, target: str, options: Mapping[str, Any] | None = None) -> ScanResult:
    spec = get_wstg_native_spec(capability_id)
    validate_wstg_native_options(capability_id, options or {})
    canonical_target = validate_authorized_web_target(target)
    try:
        with pinned_http_operation(canonical_target):
            observation = _PROBES[capability_id](canonical_target)
    except Exception as exc:
        # Authorization failures are caught before this service by the scan binding.
        # Runtime/network uncertainty is evidence, not a vulnerability and not a worker failure.
        observation = {
            **_base_observation(capability_id),
            'abstained': True,
            'abstention_reason': f'{type(exc).__name__}: {str(exc)}'[:500],
        }
    payload = {
        'schema': 'aegis.wstg-native-observations.v1',
        'count': 1,
        'observations': [observation],
    }
    return ScanResult(
        tool=spec.binary,
        target=canonical_target,
        exit_code=0,
        stdout=json.dumps(payload, sort_keys=True, separators=(',', ':')),
        stderr='',
    )


def normalize_wstg_native_output(capability_id: str, raw: str) -> dict[str, Any]:
    expected = _EXPECTED_KINDS.get(capability_id)
    if expected is None:
        raise ValueError(f'Unknown WSTG native capability: {capability_id}')
    try:
        data = json.loads(raw or '{}')
    except (TypeError, ValueError, json.JSONDecodeError):
        data = {}
    values = data.get('observations') if isinstance(data, dict) else []
    observations: list[dict[str, Any]] = []
    for item in values[:8] if isinstance(values, list) else []:
        if not isinstance(item, dict) or item.get('kind') != expected:
            continue
        safe: dict[str, Any] = {
            'kind': expected,
            'capability_id': capability_id,
            'wstg_ids': list(_WSTG_IDS[capability_id]),
            'final_decision': False,
            'observation_only': True,
            'abstained': item.get('abstained') is True,
        }
        for key in (
            'transport_method', 'override_method', 'content_type', 'abstention_reason',
            'baseline_redirect_authority', 'altered_redirect_authority',
        ):
            if key in item:
                safe[key] = str(item.get(key) or '')[:500]
        for key in (
            'baseline_status', 'override_status', 'alternate_origin_status', 'altered_host_status', 'status',
        ):
            if key in item:
                try:
                    safe[key] = max(0, min(int(item.get(key) or 0), 599))
                except (TypeError, ValueError):
                    safe[key] = 0
        statuses = item.get('statuses')
        if isinstance(statuses, dict):
            safe['statuses'] = {
                str(k).upper()[:16]: max(0, min(int(v or 0), 599))
                for k, v in list(statuses.items())[:8]
                if str(k).upper() in {'GET', 'HEAD', 'OPTIONS'}
            }
        allow = item.get('allow_methods')
        if isinstance(allow, list):
            safe['allow_methods'] = [str(v).upper()[:16] for v in allow[:32]]
        for key in (
            'unsafe_methods_sent', 'response_semantics_changed', 'baseline_upgrade_accepted',
            'alternate_origin_upgrade_accepted', 'application_frames_sent', 'anonymous_access_observed',
            'redirect_authority_changed', 'network_destination_changed',
        ):
            if key in item:
                safe[key] = item.get(key) is True
        observations.append(safe)
    return {
        'schema': 'aegis.native-observations.v1',
        'count': len(observations),
        'observations': observations,
        'decision_authority': False,
    }
