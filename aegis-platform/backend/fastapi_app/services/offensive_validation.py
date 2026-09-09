from __future__ import annotations

import hashlib
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal

from django.db import transaction

from .evidence_identity import evidence_id
from .scope_authorization import require_authorized_target

SCHEMA = 'aegis.offensive-validation.v1'
ENGINE = 'aegis-offensive-validation'
MAX_BODY_BYTES = 65536
SAFE_METHODS = {'GET', 'HEAD'}
SENSITIVE_PATTERN = re.compile(
    r'(meterpreter|reverse[_\s-]*shell|/bin/sh|cmd\.exe|powershell\s+-|nc\s+-e|bash\s+-i)',
    re.IGNORECASE,
)

ProbeKind = Literal[
    'http-reachability',
    'reflected-token',
    'redirect-control',
    'semantic-browser-transport',
]


@dataclass(frozen=True)
class ProbeRequest:
    kind: ProbeKind
    method: str
    url: str
    token_sha256: str = ''
    description: str = ''


@dataclass(frozen=True)
class HTTPProbeResponse:
    status: int
    headers: dict[str, str]
    body: str
    final_url: str


@dataclass(frozen=True)
class ProbeProof:
    kind: ProbeKind
    method: str
    url: str
    status: int
    evidence_sha256: str
    exploitability_proven: bool
    confidence: str
    summary: str
    token_sha256: str = ''
    response_header_names: tuple[str, ...] = ()
    response_preview: str = ''


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


HttpClient = Callable[[ProbeRequest], HTTPProbeResponse]


def _redact(value: str, secrets_to_redact: tuple[str, ...]) -> str:
    text = str(value or '')
    for secret in secrets_to_redact:
        if secret:
            text = text.replace(secret, '[REDACTED]')
    return text[:4096]


def _assert_no_live_session_payload(value: str) -> None:
    if SENSITIVE_PATTERN.search(value or ''):
        raise ValueError('Live shell/session payloads are not part of offensive validation evidence capture')


def _authorization_scope_url(url: str) -> str:
    """Return the URL form used only for scope authorization.

    Scope authorization intentionally validates the destination authority and path
    without trusting probe query strings. Probes may need harmless query markers,
    but those markers must never widen the host/scope decision.
    """
    parsed = urllib.parse.urlparse(str(url).strip())
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('Offensive validation requires an HTTP(S) URL target')
    return urllib.parse.urlunparse(parsed._replace(query='', fragment=''))


def _require_authorized_http_url(url: str, *, resolve_dns: bool) -> None:
    require_authorized_target(_authorization_scope_url(url), url=True, resolve_dns=resolve_dns)


def _redacted_probe_url(url: str, secrets_to_redact: tuple[str, ...]) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if not query:
        return _redact(url, secrets_to_redact)
    safe_query: list[tuple[str, str]] = []
    for key, value in query:
        key_lower = key.lower()
        if 'token' in key_lower or key_lower in {'q', 'query', 'search', 'redirect', 'next', 'url', 'return'}:
            safe_query.append((key, '[REDACTED]'))
        else:
            safe_query.append((key, _redact(value, secrets_to_redact)))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(safe_query)))


def _default_http_client(probe: ProbeRequest) -> HTTPProbeResponse:
    method = probe.method.upper().strip()
    if method not in SAFE_METHODS:
        raise ValueError(f'Unsupported offensive validation HTTP method: {method}')
    _require_authorized_http_url(probe.url, resolve_dns=True)
    request = urllib.request.Request(
        probe.url,
        method=method,
        headers={'User-Agent': 'AegisScan-OffensiveValidation/1.0'},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=10) as response:
            raw_body = response.read(MAX_BODY_BYTES + 1)
            status = int(response.status)
            headers = {str(key).lower(): str(value)[:2048] for key, value in response.headers.items()}
            final_url = str(response.geturl())
    except urllib.error.HTTPError as exc:
        raw_body = exc.read(MAX_BODY_BYTES + 1)
        status = int(exc.code)
        headers = {str(key).lower(): str(value)[:2048] for key, value in exc.headers.items()}
        final_url = probe.url
    body = raw_body[:MAX_BODY_BYTES].decode('utf-8', errors='ignore')
    return HTTPProbeResponse(status=status, headers=headers, body=body, final_url=final_url)


def _candidate_url(finding: Any) -> str:
    candidates: list[str] = []
    if getattr(finding, 'url', ''):
        candidates.append(str(finding.url))
    raw_data = getattr(finding, 'raw_data', {}) if isinstance(getattr(finding, 'raw_data', {}), dict) else {}
    for key in ('url', 'target', 'target_url'):
        value = raw_data.get(key)
        if isinstance(value, str):
            candidates.append(value)
    affected = raw_data.get('affected_urls')
    if isinstance(affected, list):
        candidates.extend(str(item) for item in affected if isinstance(item, str))
    for candidate in candidates:
        parsed = urllib.parse.urlparse(candidate.strip())
        if parsed.scheme in {'http', 'https'} and parsed.hostname:
            return candidate.strip()
    raise ValueError('Finding does not contain a usable HTTP(S) target URL for validation')


def _classifiers(finding: Any) -> set[str]:
    values: set[str] = set()
    for field in ('title', 'description', 'category', 'cwe_id', 'owasp_category', 'parameter'):
        value = str(getattr(finding, field, '') or '').strip().lower()
        if value:
            values.add(value)
    tags = getattr(finding, 'tags', [])
    if isinstance(tags, list):
        values.update(str(item).strip().lower() for item in tags if str(item).strip())
    raw_data = getattr(finding, 'raw_data', {}) if isinstance(getattr(finding, 'raw_data', {}), dict) else {}
    rule_id = raw_data.get('rule_id')
    if isinstance(rule_id, str):
        values.add(rule_id.strip().lower())
    return values


def _add_query(url: str, key: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append((key, value))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def _redirect_url(url: str, parameter: str, inert_target: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    filtered = [(key, value) for key, value in query if key != parameter]
    filtered.append((parameter, inert_target))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(filtered)))


def build_validation_plan(finding: Any, *, token: str | None = None) -> list[ProbeRequest]:
    target_url = _candidate_url(finding)
    _require_authorized_http_url(target_url, resolve_dns=False)
    labels = _classifiers(finding)
    plan: list[ProbeRequest] = [ProbeRequest(
        kind='http-reachability',
        method='HEAD',
        url=target_url,
        description='Confirm the target endpoint is reachable during validation.',
    )]

    joined = ' '.join(sorted(labels))
    if 'cwe-79' in joined or 'xss' in joined or 'cross-site scripting' in joined:
        marker = token or f'aegis-{secrets.token_hex(16)}'
        plan.append(ProbeRequest(
            kind='reflected-token',
            method='GET',
            url=_add_query(target_url, 'aegis_validation_token', marker),
            token_sha256=hashlib.sha256(marker.encode()).hexdigest(),
            description='Inject a harmless one-time marker and verify whether it is reflected by the application response.',
        ))

    if 'cwe-601' in joined or 'open redirect' in joined or 'unvalidated redirect' in joined:
        parameter = str(getattr(finding, 'parameter', '') or 'next').strip() or 'next'
        inert = 'https://aegis-validation.invalid/redirect-sink'
        plan.append(ProbeRequest(
            kind='redirect-control',
            method='GET',
            url=_redirect_url(target_url, parameter, inert),
            token_sha256=hashlib.sha256(inert.encode()).hexdigest(),
            description='Test redirect control with an inert sink domain without following the redirect.',
        ))

    if 'cwe-319' in joined or 'browser.insecure-form-action' in joined or 'browser.mixed-content' in joined:
        plan.append(ProbeRequest(
            kind='semantic-browser-transport',
            method='HEAD',
            url=target_url,
            description='Confirm browser-derived transport downgrade evidence already attached to the finding.',
        ))
    return plan


def _proof_from_http(
    probe: ProbeRequest,
    response: HTTPProbeResponse,
    *,
    secrets_to_redact: tuple[str, ...],
) -> ProbeProof:
    body = response.body or ''
    headers = {key.lower(): value for key, value in response.headers.items()}
    stored_url = _redacted_probe_url(probe.url, secrets_to_redact)
    evidence_material = json.dumps({
        'kind': probe.kind,
        'method': probe.method,
        'url': stored_url,
        'status': response.status,
        'headers': headers,
        'body_sha256': hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest(),
    }, sort_keys=True, separators=(',', ':'))
    proven = False
    summary = 'Target reached; validation evidence captured.'
    confidence = 'low'
    if probe.kind == 'reflected-token':
        token = urllib.parse.parse_qs(urllib.parse.urlparse(probe.url).query).get('aegis_validation_token', [''])[0]
        proven = bool(token and token in body)
        confidence = 'high' if proven else 'medium'
        summary = 'Harmless validation marker was reflected by the response.' if proven else 'Marker was not reflected by the response.'
    elif probe.kind == 'redirect-control':
        location = headers.get('location', '')
        proven = 300 <= response.status < 400 and location.startswith('https://aegis-validation.invalid/')
        confidence = 'high' if proven else 'medium'
        summary = 'Redirect target is externally controllable.' if proven else 'Redirect control was not observed.'
    return ProbeProof(
        kind=probe.kind,
        method=probe.method,
        url=stored_url,
        status=response.status,
        evidence_sha256=hashlib.sha256(evidence_material.encode()).hexdigest(),
        exploitability_proven=proven,
        confidence=confidence,
        summary=summary,
        token_sha256=probe.token_sha256,
        response_header_names=tuple(sorted(headers)[:100]),
        response_preview=_redact(body, secrets_to_redact),
    )


def _semantic_browser_proof(finding: Any, probe: ProbeRequest, *, secrets_to_redact: tuple[str, ...]) -> ProbeProof:
    raw_data = getattr(finding, 'raw_data', {}) if isinstance(getattr(finding, 'raw_data', {}), dict) else {}
    affected = raw_data.get('affected_urls') if isinstance(raw_data.get('affected_urls'), list) else []
    material = json.dumps({'finding_id': str(getattr(finding, 'id', '')), 'affected_urls': affected}, sort_keys=True)
    return ProbeProof(
        kind=probe.kind,
        method='EVIDENCE',
        url=_redacted_probe_url(probe.url, secrets_to_redact),
        status=0,
        evidence_sha256=hashlib.sha256(material.encode()).hexdigest(),
        exploitability_proven=bool(affected),
        confidence='high' if affected else 'medium',
        summary='Existing browser evidence demonstrates a transport downgrade path.' if affected else 'No browser downgrade URL was present in finding evidence.',
        response_header_names=(),
        response_preview='',
    )


def run_offensive_validation(
    *,
    finding: Any,
    actor: Any | None = None,
    profile: str = 'standard',
    http_client: HttpClient | None = None,
    validation_run: Any | None = None,
    secrets_to_redact: tuple[str, ...] = (),
) -> dict[str, Any]:
    target_url = _candidate_url(finding)
    _assert_no_live_session_payload(json.dumps(getattr(finding, 'raw_data', {}), default=str))
    _require_authorized_http_url(target_url, resolve_dns=False)
    actor = actor or getattr(getattr(finding, 'scan', None), 'initiated_by', None)
    if actor is None:
        raise ValueError('Offensive validation requires an actor for audit attribution')

    from django_project.evidence.models import Evidence, ValidationRun
    from django_project.vulnerabilities.models import Vulnerability

    client = http_client or _default_http_client
    plan = build_validation_plan(finding)
    now = datetime.now(timezone.utc)

    with transaction.atomic():
        run = validation_run or ValidationRun.objects.create(
            user=actor,
            finding=finding,
            target_type='url',
            target_value=_authorization_scope_url(target_url),
            scope=str(getattr(getattr(finding, 'project', None), 'id', '')),
            profile=profile,
            engines=[ENGINE],
            authorized=True,
            status=ValidationRun.Status.RUNNING,
            progress=10,
            current_phase='offensive-validation',
            started_at=now,
        )
        if validation_run:
            run.status = ValidationRun.Status.RUNNING
            run.progress = 10
            run.current_phase = 'offensive-validation'
            run.started_at = run.started_at or now
            run.save(update_fields=['status', 'progress', 'current_phase', 'started_at'])

    proofs: list[ProbeProof] = []
    errors: list[str] = []
    for probe in plan:
        try:
            _assert_no_live_session_payload(probe.url)
            if probe.kind == 'semantic-browser-transport':
                proofs.append(_semantic_browser_proof(finding, probe, secrets_to_redact=secrets_to_redact))
            else:
                proofs.append(_proof_from_http(probe, client(probe), secrets_to_redact=secrets_to_redact))
        except Exception as exc:
            errors.append(str(exc)[:1000])

    proven = any(item.exploitability_proven for item in proofs)
    state = 'confirmed' if proven else 'not_reproduced'
    confidence = 'high' if proven else 'medium' if proofs else 'low'
    result = {
        'schema': SCHEMA,
        'engine': ENGINE,
        'finding_id': str(finding.id),
        'target_url': _redacted_probe_url(target_url, secrets_to_redact),
        'profile': profile,
        'status': 'completed' if proofs else 'failed',
        'exploitability': {
            'state': state,
            'confidence': confidence,
            'proof_count': len(proofs),
            'proven_count': sum(1 for item in proofs if item.exploitability_proven),
        },
        'probes': [asdict(item) for item in proofs],
        'errors': errors,
        'runtime': {
            'live_session_opened': False,
            'unrestricted_shell_opened': False,
            'raw_secret_material_stored': False,
        },
    }
    serialized = json.dumps(result, sort_keys=True, separators=(',', ':'))
    for secret in secrets_to_redact:
        if secret and secret in serialized:
            raise ValueError('Offensive validation result contains raw secret material')

    completed = datetime.now(timezone.utc)
    with transaction.atomic():
        run.status = ValidationRun.Status.COMPLETED if proofs else ValidationRun.Status.FAILED
        run.progress = 100
        run.current_phase = 'completed' if proofs else 'failed'
        run.completed_at = completed
        run.result = result
        run.error_message = '\n'.join(errors)[:10000]
        run.save(update_fields=['status', 'progress', 'current_phase', 'completed_at', 'result', 'error_message'])

        evidence, _ = Evidence.objects.update_or_create(
            id=evidence_id('validation', str(run.id), ENGINE, 'exploitability_proof', str(finding.id)),
            defaults={
                'scan': getattr(finding, 'scan', None),
                'asset': getattr(finding, 'asset', None),
                'finding': finding,
                'source': ENGINE,
                'evidence_type': 'exploitability_proof',
                'raw_output': serialized,
                'metadata': {
                    'schema': SCHEMA,
                    'validation_run_id': str(run.id),
                    'finding_id': str(finding.id),
                    'target_url': _authorization_scope_url(target_url),
                    'profile': profile,
                    'proof_count': len(proofs),
                    'proven_count': result['exploitability']['proven_count'],
                    'runtime': result['runtime'],
                },
                'collected_by': actor,
            },
        )

        finding.validation_status = state
        finding.validated_at = completed
        finding.validated_by = actor
        finding.verified_evidence_count = Evidence.objects.filter(finding=finding).count()
        if proven:
            finding.confidence = Vulnerability.Confidence.CONFIRMED
            finding.exploitability = max(float(getattr(finding, 'exploitability', 0) or 0), 0.9)
        finding.save(update_fields=[
            'validation_status', 'validated_at', 'validated_by', 'verified_evidence_count',
            'confidence', 'exploitability', 'updated_at',
        ])
    return {**result, 'validation_run_id': str(run.id), 'evidence_id': str(evidence.id)}
