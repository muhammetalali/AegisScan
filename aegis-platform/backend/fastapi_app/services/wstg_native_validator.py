#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any

from fastapi_app.services.pinned_http import (
    PinnedHTTPDestination,
    origin,
    pin_http_destination,
    pinned_http_operation,
    request_pinned,
)

_SCHEMA = 'aegis.wstg-native-validator.v1'
_PARAMETER_RE = re.compile(r'^[A-Za-z0-9_$.\-\[\]]{1,128}$')
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_CONTROL_HEADER = 'X-Aegis-Canary-Control'
_MAX_RESPONSE_BYTES = 262144


def _finding(
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    remediation: str,
    *,
    location: str,
    cwe_id: str = '',
    owasp_category: str = '',
    confidence: str = 'high',
    parameter: str = '',
) -> dict[str, Any]:
    return {
        'kind': 'wstg-native-finding',
        'rule_id': rule_id,
        'title': title,
        'description': description,
        'severity': severity,
        'confidence': confidence,
        'category': 'wstg-native-validation',
        'location': location[:2048],
        'parameter': parameter[:128],
        'cwe_id': cwe_id[:64],
        'owasp_category': owasp_category[:200],
        'remediation': remediation[:5000],
    }


def _summary(validator: str, target: str, **details: Any) -> dict[str, Any]:
    return {
        'kind': 'wstg-native-validation',
        'validator': validator,
        'target_origin': _origin_text(target),
        **details,
    }


def _origin_text(url: str) -> str:
    scheme, host, port = origin(url)
    default = 443 if scheme == 'https' else 80
    authority = host if port == default else f'{host}:{port}'
    return f'{scheme}://{authority}'


def _body_fingerprint(response) -> dict[str, Any]:
    return {
        'status': int(response.status),
        'content_type': response.content_type[:200],
        'body_length': len(response.body),
        'body_sha256': hashlib.sha256(response.body).hexdigest(),
    }


def _selected_parameter(target: str, explicit: str | None) -> str | None:
    if explicit:
        candidate = str(explicit).strip()
        if not _PARAMETER_RE.fullmatch(candidate):
            raise ValueError('parameter must contain only a bounded URL-parameter name')
        return candidate
    parsed = urllib.parse.urlsplit(target)
    for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256):
        if _PARAMETER_RE.fullmatch(name):
            return name
    return None


def _replace_parameter(target: str, name: str, values: list[str]) -> str:
    parsed = urllib.parse.urlsplit(target)
    existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256)
    rebuilt: list[tuple[str, str]] = [(key, value) for key, value in existing if key != name]
    rebuilt.extend((name, value) for value in values)
    query = urllib.parse.urlencode(rebuilt, doseq=True)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', query, ''))


def validate_http_method_policy(target: str) -> dict[str, Any]:
    with pinned_http_operation(target) as destination:
        response = request_pinned('OPTIONS', target, timeout=10, max_body_bytes=65536, destination=destination)
        allow_values = ','.join(
            value for name, value in response.headers.items()
            if name in {'allow', 'access-control-allow-methods'}
        )
        methods = sorted({
            token.strip().upper()
            for token in allow_values.split(',')
            if token.strip() and re.fullmatch(r'[A-Za-z]{1,20}', token.strip())
        })
        observations: list[dict[str, Any]] = [
            _summary(
                'http-method-policy',
                target,
                status='observed',
                request_count=1,
                advertised_methods=methods,
                resolved_ips=list(destination.resolved_ips),
                response_status=response.status,
            )
        ]
        dangerous = sorted(set(methods) & {'TRACE', 'CONNECT'})
        if dangerous:
            observations.append(_finding(
                'wstg.http-method-dangerous-advertisement',
                'Dangerous HTTP method advertised',
                f'The authorized endpoint explicitly advertises dangerous method(s): {", ".join(dangerous)}.',
                'medium',
                'Disable TRACE/CONNECT unless explicitly required and enforce a strict method allow-list at every proxy and application hop.',
                location=target,
                cwe_id='CWE-749',
                owasp_category='A05:2021-Security Misconfiguration',
            ))
        state_changing = sorted(set(methods) & {'PUT', 'DELETE', 'PATCH'})
        if state_changing:
            observations.append({
                'kind': 'wstg-native-observation',
                'validator': 'http-method-policy',
                'observation': 'state-changing-methods-advertised',
                'methods': state_changing,
                'location': target[:2048],
            })
        return {'schema': _SCHEMA, 'capability_id': 'web.http-method-policy', 'observations': observations}


def validate_duplicate_parameter_semantics(target: str, parameter: str | None) -> dict[str, Any]:
    selected = _selected_parameter(target, parameter)
    if selected is None:
        return {
            'schema': _SCHEMA,
            'capability_id': 'web.duplicate-parameter-semantics',
            'observations': [_summary(
                'duplicate-parameter-semantics',
                target,
                status='inconclusive',
                reason='No bounded query parameter was supplied or discovered on the target URL.',
                request_count=0,
            )],
        }

    alpha = 'aegis-alpha'
    beta = 'aegis-beta'
    with pinned_http_operation(target) as destination:
        baseline_a = request_pinned('GET', target, timeout=10, max_body_bytes=_MAX_RESPONSE_BYTES, destination=destination)
        baseline_b = request_pinned('GET', target, timeout=10, max_body_bytes=_MAX_RESPONSE_BYTES, destination=destination)
        base_a = _body_fingerprint(baseline_a)
        base_b = _body_fingerprint(baseline_b)
        if base_a != base_b:
            return {
                'schema': _SCHEMA,
                'capability_id': 'web.duplicate-parameter-semantics',
                'observations': [_summary(
                    'duplicate-parameter-semantics',
                    target,
                    status='inconclusive',
                    reason='Baseline response was not stable enough for duplicate-parameter comparison.',
                    parameter=selected,
                    request_count=2,
                    resolved_ips=list(destination.resolved_ips),
                )],
            }

        first_url = _replace_parameter(target, selected, [alpha, beta])
        second_url = _replace_parameter(target, selected, [beta, alpha])
        first = request_pinned('GET', first_url, timeout=10, max_body_bytes=_MAX_RESPONSE_BYTES, destination=destination)
        second = request_pinned('GET', second_url, timeout=10, max_body_bytes=_MAX_RESPONSE_BYTES, destination=destination)
        fp_first = _body_fingerprint(first)
        fp_second = _body_fingerprint(second)
        differs = fp_first != fp_second
        observations: list[dict[str, Any]] = [_summary(
            'duplicate-parameter-semantics',
            target,
            status='observed',
            parameter=selected,
            request_count=4,
            order_sensitive=differs,
            resolved_ips=list(destination.resolved_ips),
            first_response=fp_first,
            second_response=fp_second,
        )]
        if differs:
            observations.append(_finding(
                'wstg.duplicate-parameter-order-sensitive',
                'Duplicate HTTP parameter semantics are order-sensitive',
                'Reversing two benign duplicate values changed the response semantics while the baseline was stable.',
                'medium',
                'Reject duplicate security-sensitive parameters or canonicalize them once at the edge and application using one documented precedence rule.',
                location=target,
                parameter=selected,
                cwe_id='CWE-235',
                owasp_category='A04:2021-Insecure Design',
            ))
        return {'schema': _SCHEMA, 'capability_id': 'web.duplicate-parameter-semantics', 'observations': observations}


def _canary_configuration() -> tuple[str, str]:
    raw_base = os.getenv('AEGIS_SSRF_CANARY_BASE_URL', '').strip().rstrip('/')
    control = os.getenv('AEGIS_SSRF_CANARY_CONTROL_TOKEN', '').strip()
    if not raw_base or not _TOKEN_RE.fullmatch(control):
        raise RuntimeError('SSRF canary service is not configured')
    parsed = urllib.parse.urlsplit(raw_base)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError('SSRF canary base URL is invalid')
    if parsed.query or parsed.fragment:
        raise RuntimeError('SSRF canary base URL is invalid')
    if parsed.scheme == 'http' and parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}:
        raise RuntimeError('SSRF canary control plane requires HTTPS outside loopback')
    base_path = parsed.path.rstrip('/')
    origin_text = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, base_path, '', ''))
    return origin_text, control


def _canary_request(base: str, control: str, path: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    request = urllib.request.Request(
        base + path,
        data=data,
        method='POST' if data is not None else 'GET',
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            _CONTROL_HEADER: control,
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=5) as response:
            raw = response.read(65537)
    except Exception as exc:
        raise RuntimeError('SSRF canary control request failed') from exc
    if len(raw) > 65536:
        raise RuntimeError('SSRF canary control response exceeded size limit')
    try:
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('SSRF canary control response was invalid') from exc
    if not isinstance(result, dict):
        raise RuntimeError('SSRF canary control response was invalid')
    return result


def validate_ssrf_canary(target: str, parameter: str | None) -> dict[str, Any]:
    selected = _selected_parameter(target, parameter)
    if selected is None:
        return {
            'schema': _SCHEMA,
            'capability_id': 'web.ssrf-canary-validation',
            'observations': [_summary(
                'ssrf-canary-validation',
                target,
                status='inconclusive',
                reason='No bounded URL parameter was supplied or discovered for SSRF canary validation.',
                request_count=0,
            )],
        }
    try:
        canary_base, control = _canary_configuration()
    except RuntimeError as exc:
        return {
            'schema': _SCHEMA,
            'capability_id': 'web.ssrf-canary-validation',
            'observations': [_summary(
                'ssrf-canary-validation',
                target,
                status='inconclusive',
                reason=str(exc),
                parameter=selected,
                request_count=0,
            )],
        }

    token = secrets.token_hex(32)
    token_fingerprint = hashlib.sha256(token.encode('ascii')).hexdigest()
    registered = _canary_request(canary_base, control, '/api/v1/ssrf-canary/register', payload={'token': token})
    if registered.get('status') != 'registered':
        raise RuntimeError('SSRF canary service did not register probe')
    callback_url = f'{canary_base}/api/v1/ssrf-canary/callback/{token}'
    probe_url = _replace_parameter(target, selected, [callback_url])

    with pinned_http_operation(target) as destination:
        response = request_pinned('GET', probe_url, timeout=15, max_body_bytes=_MAX_RESPONSE_BYTES, destination=destination)
        observed = False
        for _ in range(20):
            state = _canary_request(canary_base, control, f'/api/v1/ssrf-canary/status/{token}')
            if state.get('observed') is True:
                observed = True
                break
            time.sleep(0.25)

        observations: list[dict[str, Any]] = [_summary(
            'ssrf-canary-validation',
            target,
            status='observed',
            parameter=selected,
            request_count=1,
            callback_observed=observed,
            target_response_status=response.status,
            canary_origin=_origin_text(canary_base),
            canary_token_fingerprint=token_fingerprint,
            resolved_ips=list(destination.resolved_ips),
        )]
        if observed:
            observations.append(_finding(
                'wstg.ssrf-canary-callback-observed',
                'Server-side request forgery canary callback observed',
                'A unique Aegis-controlled canary URL supplied in the authorized request was fetched by the target environment.',
                'high',
                'Use strict destination allow-lists, normalize and validate URL schemes/hosts after redirects, block private/link-local metadata ranges, and route outbound fetches through a controlled egress proxy.',
                location=target,
                parameter=selected,
                cwe_id='CWE-918',
                owasp_category='A10:2021-Server-Side Request Forgery (SSRF)',
            ))
        return {'schema': _SCHEMA, 'capability_id': 'web.ssrf-canary-validation', 'observations': observations}


def _socket_address(address: str, port: int):
    import ipaddress
    parsed = ipaddress.ip_address(address)
    if parsed.version == 6:
        return (str(parsed), port, 0, 0)
    return (str(parsed), port)


def _tls_version_supported(destination: PinnedHTTPDestination, version: ssl.TLSVersion) -> bool:
    for address in destination.resolved_ips:
        raw = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(5)
            raw.connect(_socket_address(address, destination.port))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            try:
                context.set_ciphers('DEFAULT:@SECLEVEL=0')
            except ssl.SSLError:
                pass
            with context.wrap_socket(raw, server_hostname=destination.host) as wrapped:
                wrapped.do_handshake()
                return True
        except (OSError, ssl.SSLError, ValueError):
            try:
                raw.close()
            except OSError:
                pass
            continue
    return False


def validate_tls_posture(target: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme.lower() == 'http':
        return {
            'schema': _SCHEMA,
            'capability_id': 'tls.posture',
            'observations': [
                _summary('tls-posture', target, status='observed', tls=False, request_count=0),
                _finding(
                    'wstg.cleartext-http-transport',
                    'Cleartext HTTP transport is in use',
                    'The authorized target is served over cleartext HTTP rather than TLS.',
                    'medium',
                    'Serve the endpoint exclusively over HTTPS, redirect HTTP to HTTPS, and deploy HSTS after migration validation.',
                    location=target,
                    cwe_id='CWE-319',
                    owasp_category='A02:2021-Cryptographic Failures',
                ),
            ],
        }

    destination = pin_http_destination(target)
    supported: dict[str, bool] = {}
    candidates = (
        ('TLSv1.0', getattr(ssl.TLSVersion, 'TLSv1', None)),
        ('TLSv1.1', getattr(ssl.TLSVersion, 'TLSv1_1', None)),
        ('TLSv1.2', getattr(ssl.TLSVersion, 'TLSv1_2', None)),
        ('TLSv1.3', getattr(ssl.TLSVersion, 'TLSv1_3', None)),
    )
    for label, version in candidates:
        supported[label] = bool(version is not None and _tls_version_supported(destination, version))

    certificate_valid = True
    certificate_error = ''
    try:
        request_pinned('HEAD', target, timeout=10, max_body_bytes=0, destination=destination)
    except RuntimeError as exc:
        cause = exc.__cause__
        if isinstance(cause, ssl.SSLCertVerificationError):
            certificate_valid = False
            certificate_error = 'certificate-verification-failed'
        else:
            certificate_error = 'tls-baseline-request-failed'

    observations: list[dict[str, Any]] = [_summary(
        'tls-posture',
        target,
        status='observed' if not certificate_error or not certificate_valid else 'inconclusive',
        tls=True,
        supported_protocols=[name for name, enabled in supported.items() if enabled],
        certificate_valid=certificate_valid,
        certificate_status=certificate_error or 'verified',
        resolved_ips=list(destination.resolved_ips),
        request_count=1,
    )]
    weak = [name for name in ('TLSv1.0', 'TLSv1.1') if supported.get(name)]
    if weak:
        observations.append(_finding(
            'wstg.weak-tls-protocol-enabled',
            'Legacy TLS protocol is enabled',
            f'The authorized endpoint accepted deprecated protocol(s): {", ".join(weak)}.',
            'high',
            'Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer with modern cipher suites.',
            location=target,
            cwe_id='CWE-326',
            owasp_category='A02:2021-Cryptographic Failures',
        ))
    if not certificate_valid:
        observations.append(_finding(
            'wstg.tls-certificate-verification-failed',
            'TLS certificate validation failed',
            'The endpoint certificate could not be validated by the scanner trust store for the authorized hostname.',
            'high',
            'Deploy a valid certificate chain for the authorized hostname and ensure certificate validity, hostname coverage, and trusted issuer configuration.',
            location=target,
            cwe_id='CWE-295',
            owasp_category='A02:2021-Cryptographic Failures',
        ))
    return {'schema': _SCHEMA, 'capability_id': 'tls.posture', 'observations': observations}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='AegisScan bounded WSTG native validator')
    parser.add_argument('--mode', required=True, choices=(
        'http-method-policy',
        'duplicate-parameter-semantics',
        'ssrf-canary-validation',
        'tls-posture',
    ))
    parser.add_argument('target')
    parser.add_argument('--parameter')
    args = parser.parse_args()
    if args.parameter and not _PARAMETER_RE.fullmatch(args.parameter):
        parser.error('--parameter is invalid')
    return args


def main() -> int:
    args = _parse_args()
    try:
        if args.mode == 'http-method-policy':
            result = validate_http_method_policy(args.target)
        elif args.mode == 'duplicate-parameter-semantics':
            result = validate_duplicate_parameter_semantics(args.target, args.parameter)
        elif args.mode == 'ssrf-canary-validation':
            result = validate_ssrf_canary(args.target, args.parameter)
        else:
            result = validate_tls_posture(args.target)
    except Exception as exc:
        result = {
            'schema': _SCHEMA,
            'error': type(exc).__name__,
            'summary': str(exc)[:500],
            'observations': [],
        }
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
