from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import secrets
import socket
import ssl
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal

from django.db import transaction

from .evidence_identity import evidence_id
from .scope_authorization import require_authorized_target
from .authorization_guard import current_asset_authorization

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
    observation_confirmed: bool = False
    source_evidence_id: str = ''


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


def _require_authorized_http_url(url: str, *, resolve_dns: bool) -> tuple[str, ...]:
    return require_authorized_target(_authorization_scope_url(url), url=True, resolve_dns=resolve_dns)


def _redacted_probe_url(url: str, secrets_to_redact: tuple[str, ...]) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    # Query names and values can both carry credentials. Retain only their count.
    safe_query = urllib.parse.urlencode([('redacted', str(len(query)))]) if query else ''
    return _redact(urllib.parse.urlunparse(parsed._replace(query=safe_query, fragment='')), secrets_to_redact)


def _default_http_client(probe: ProbeRequest) -> HTTPProbeResponse:
    method = probe.method.upper().strip()
    if method not in SAFE_METHODS:
        raise ValueError(f'Unsupported offensive validation HTTP method: {method}')
    addresses = _require_authorized_http_url(probe.url, resolve_dns=True)
    if not addresses:
        raise ValueError('Validation requires an explicitly resolved destination')
    parsed = urllib.parse.urlsplit(probe.url)
    host = parsed.hostname.encode('idna').decode('ascii')
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    address = ipaddress.ip_address(addresses[0])
    # Connect to the exact checked IP. Preserve the origin for Host and TLS SNI;
    # do not re-resolve DNS, consult proxy environment variables, or follow Location.
    connection = http.client.HTTPConnection(host, port, timeout=10)
    sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(10)
        sock.connect((str(address), port))
        if parsed.scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection.sock = sock
        path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
        connection.request(method, path, headers={'User-Agent': 'AegisScan-OffensiveValidation/1.0'})
        response = connection.getresponse()
        raw_body = response.read(MAX_BODY_BYTES + 1)
        status = response.status
        headers = {str(key).lower(): str(value)[:2048] for key, value in response.getheaders()}
    finally:
        connection.close()
        sock.close()
    body = raw_body[:MAX_BODY_BYTES].decode('utf-8', errors='ignore')
    return HTTPProbeResponse(status=status, headers=headers, body=body, final_url=probe.url)


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
    query = [(name, item) for name, item in query if name != key]
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
        inert = f'https://aegis-validation.invalid/{secrets.token_hex(16)}'
        plan.append(ProbeRequest(
            kind='redirect-control',
            method='GET',
            url=_redirect_url(target_url, parameter, inert),
            token_sha256=hashlib.sha256(inert.encode()).hexdigest(),
            description='Test redirect control with an inert sink domain without following the redirect.',
        ))

    if 'cwe-319' in joined or 'browser.insecure-form-action' in joined or 'browser.mixed-content' in joined:
        return [ProbeRequest(
            kind='semantic-browser-transport',
            method='HEAD',
            url=target_url,
            description='Confirm browser-derived transport downgrade evidence already attached to the finding.',
        )]
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
        reflected = bool(token and token in body)
        # Reflection alone is compatible with correctly escaped HTML or plain
        # text. It cannot establish JavaScript execution or confirm CWE-79.
        summary = 'Marker reflection observed; script execution remains unproven.' if reflected else 'Marker was not reflected; XSS remains unproven.'
    elif probe.kind == 'redirect-control':
        location = headers.get('location', '')
        proven = 300 <= response.status < 400 and hashlib.sha256(location.encode()).hexdigest() == probe.token_sha256
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
        response_header_names=tuple(sorted(set(headers) & {'content-type', 'location', 'content-security-policy', 'strict-transport-security'})),
        response_preview='',
        observation_confirmed=bool(probe.kind == 'reflected-token' and token and token in body),
    )


def _semantic_browser_proof(finding: Any, probe: ProbeRequest, *, secrets_to_redact: tuple[str, ...]) -> ProbeProof:
    from django_project.evidence.models import Evidence

    raw_data = getattr(finding, 'raw_data', {}) if isinstance(getattr(finding, 'raw_data', {}), dict) else {}
    affected = raw_data.get('affected_urls') if isinstance(raw_data.get('affected_urls'), list) else []
    rule = raw_data.get('rule_id')
    field = {'browser.insecure-form-action': 'insecure_form_actions', 'browser.mixed-content': 'mixed_content_urls'}.get(rule)
    source = None
    for evidence in Evidence.objects.filter(scan_id=finding.scan_id, asset_id=finding.asset_id, source='browser-security').order_by('-collected_at')[:20]:
        if hashlib.sha256(evidence.raw_output.encode('utf-8', errors='replace')).hexdigest() != evidence.sha256:
            continue
        try:
            data = json.loads(evidence.raw_output)
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict) or data.get('schema') != 'aegis.browser-security.v1' or data.get('target_url') != finding.asset.configuration.get('url'):
            continue
        if rule == 'browser.mixed-content' and urllib.parse.urlsplit(data['target_url']).scheme != 'https':
            continue
        observations = data.get('observations')
        if not isinstance(observations, list):
            continue
        for observation in observations:
            if not isinstance(observation, dict) or observation.get('kind') != 'browser-dom-security-snapshot':
                continue
            values = observation.get(field, []) if field else []
            if isinstance(values, list) and any(isinstance(url, str) and url in affected and urllib.parse.urlsplit(url).scheme == 'http' for url in values):
                source = evidence
                break
        if source:
            break
    material = json.dumps({'finding_id': str(finding.id), 'source_evidence_id': str(source.id) if source else '', 'source_sha256': source.sha256 if source else ''}, sort_keys=True)
    return ProbeProof(
        kind=probe.kind,
        method='EVIDENCE',
        url=_redacted_probe_url(probe.url, secrets_to_redact),
        status=0,
        evidence_sha256=hashlib.sha256(material.encode()).hexdigest(),
        exploitability_proven=source is not None,
        confidence='high' if source else 'low',
        summary='Linked browser evidence confirms the cleartext transport finding.' if source else 'No matching browser evidence establishes the transport finding.',
        response_header_names=(),
        response_preview='',
        source_evidence_id=str(source.id) if source else '',
    )


def _locked_context(finding_id: Any, actor: Any, target_url: str, decision_id: Any = None):
    """Caller holds a short transaction; no network work runs under these locks."""
    from django.contrib.auth import get_user_model
    from django_project.assets.models import Asset
    from django_project.projects.models import Project, ProjectMembership
    from django_project.vulnerabilities.models import Vulnerability

    finding = Vulnerability.objects.select_for_update().get(pk=finding_id)
    if not get_user_model().objects.filter(pk=actor.pk, is_active=True).exists():
        raise PermissionError('Validation requires an active project actor')
    owner = Project.objects.filter(pk=finding.project_id, owner_id=actor.pk).exists()
    member = ProjectMembership.objects.filter(project_id=finding.project_id, user_id=actor.pk, role__in=['owner', 'admin', 'member']).exists()
    if not owner and not member:
        raise PermissionError('Actor cannot execute validation in this project')
    if not finding.asset_id or not finding.scan_id:
        raise PermissionError('Validation requires a persisted asset and scan')
    asset = Asset.objects.select_for_update().get(pk=finding.asset_id)
    if asset.project_id != finding.project_id or finding.scan.project_id != finding.project_id or finding.scan.asset_id != asset.id:
        raise PermissionError('Finding, scan and asset project identities do not match')
    decision, reason = current_asset_authorization(asset)
    if decision is None:
        raise PermissionError(reason)
    if decision_id is not None and decision.pk != decision_id:
        raise PermissionError('Validation authorization has been superseded')
    if _authorization_scope_url(target_url) != _authorization_scope_url(decision.target_snapshot):
        raise PermissionError('Finding target does not match the authorized asset endpoint')
    if _candidate_url(finding) != target_url:
        raise PermissionError('Finding target changed during validation')
    _require_authorized_http_url(target_url, resolve_dns=False)
    finding.asset = asset
    return finding, decision


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
    for probe in plan:
        _assert_no_live_session_payload(probe.url)
    now = datetime.now(timezone.utc)

    with transaction.atomic():
        run = ValidationRun.objects.select_for_update().get(pk=validation_run.pk) if validation_run else None
        if run and (run.finding_id != finding.pk or run.user_id != actor.pk or run.engines != [ENGINE]):
            raise PermissionError('Validation run identity does not match the finding and actor')
        finding, decision = _locked_context(finding.pk, actor, target_url, run.authorization_decision_id if run else None)
        if run:
            if not run.authorized or run.authorization_decision_id is None or run.target_value != decision.target_snapshot:
                raise PermissionError('Validation run has no matching bound authorization')
            if run.status == ValidationRun.Status.COMPLETED:
                if not Evidence.objects.filter(pk=run.result.get('evidence_id'), finding=finding, source=ENGINE).exists():
                    raise ValueError('Completed validation is missing its evidence')
                return run.result
            if run.status != ValidationRun.Status.QUEUED:
                return run.result or {'validation_run_id': str(run.id), 'status': run.status}
        run = run or ValidationRun.objects.create(
            user=actor,
            finding=finding,
            target_type='url',
            target_value=decision.target_snapshot,
            scope=str(getattr(getattr(finding, 'project', None), 'id', '')),
            profile=profile,
            engines=[ENGINE],
            authorized=True,
            authorization_decision=decision,
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
            with transaction.atomic():
                current = ValidationRun.objects.select_for_update().get(pk=run.pk)
                if current.status == ValidationRun.Status.CANCELLED:
                    return {'validation_run_id': str(run.id), 'status': current.status}
                finding, _ = _locked_context(finding.pk, actor, target_url, decision.pk)
            if probe.kind == 'semantic-browser-transport':
                proofs.append(_semantic_browser_proof(finding, probe, secrets_to_redact=secrets_to_redact))
            else:
                proofs.append(_proof_from_http(probe, client(probe), secrets_to_redact=secrets_to_redact))
        except Exception as exc:
            # URLs, proxy errors and target-supplied messages can contain secrets.
            errors.append(f'{probe.kind}: {type(exc).__name__}')
            break

    proven = not errors and any(item.exploitability_proven for item in proofs)
    can_disprove = not errors and any(item.kind == 'redirect-control' and 200 <= item.status < 400 for item in proofs)
    state = 'confirmed' if proven else 'not_reproduced' if can_disprove else 'inconclusive'
    confidence = 'high' if proven else 'medium' if proofs else 'low'
    successful = bool(proofs) and not errors
    proof_id = evidence_id('validation', str(run.id), ENGINE, 'exploitability_proof', str(finding.id))
    result = {
        'schema': SCHEMA,
        'engine': ENGINE,
        'finding_id': str(finding.id),
        'target_url': _redacted_probe_url(target_url, secrets_to_redact),
        'profile': profile,
        'status': 'completed' if successful else 'failed',
        'validation_run_id': str(run.id),
        'evidence_id': str(proof_id),
        'exploitability': {
            'state': state,
            'confidence': confidence,
            'proof_count': len(proofs),
            'proven_count': sum(1 for item in proofs if item.exploitability_proven) if not errors else 0,
        },
        'probes': [asdict(item) for item in proofs],
        'errors': errors,
        'runtime': {
            'live_session_opened': False,
            'unrestricted_shell_opened': False,
            'response_body_stored': False,
            'response_header_values_stored': False,
        },
    }
    serialized = json.dumps(result, sort_keys=True, separators=(',', ':'))
    result = json.loads(serialized)
    for secret in secrets_to_redact:
        if secret and secret in serialized:
            raise ValueError('Offensive validation result contains raw secret material')

    completed = datetime.now(timezone.utc)
    with transaction.atomic():
        run = ValidationRun.objects.select_for_update().get(pk=run.pk)
        if run.status == ValidationRun.Status.CANCELLED:
            return {'validation_run_id': str(run.id), 'status': run.status}
        try:
            finding, _ = _locked_context(finding.pk, actor, target_url, decision.pk)
        except (PermissionError, ValueError):
            run.status = ValidationRun.Status.FAILED
            run.current_phase = 'authorization-denied'
            run.error_message = 'Authorization changed during validation; evidence was not persisted'
            run.completed_at = completed
            run.save(update_fields=['status', 'current_phase', 'error_message', 'completed_at'])
            return {'validation_run_id': str(run.id), 'status': run.status}
        run.status = ValidationRun.Status.COMPLETED if successful else ValidationRun.Status.FAILED
        run.progress = 100
        run.current_phase = result['status']
        run.completed_at = completed
        run.result = result
        run.error_message = '\n'.join(errors)[:10000]
        run.save(update_fields=['status', 'progress', 'current_phase', 'completed_at', 'result', 'error_message'])

        evidence, _ = Evidence.objects.get_or_create(
            id=proof_id,
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
                    'target_url': _redacted_probe_url(target_url, secrets_to_redact),
                    'authorization_decision_id': str(decision.id),
                    'profile': profile,
                    'proof_count': len(proofs),
                    'proven_count': result['exploitability']['proven_count'],
                    'runtime': result['runtime'],
                },
                'collected_by': actor,
            },
        )

        if not successful:
            return result
        finding.validation_status = state
        finding.validated_at = completed
        finding.validated_by = actor
        finding.verified_evidence_count = max(finding.verified_evidence_count, Evidence.objects.filter(finding=finding, metadata__proven_count__gt=0).count())
        if proven:
            finding.confidence = Vulnerability.Confidence.CONFIRMED
            finding.exploitability = max(float(getattr(finding, 'exploitability', 0) or 0), 0.9)
        finding.save(update_fields=[
            'validation_status', 'validated_at', 'validated_by', 'verified_evidence_count',
            'confidence', 'exploitability', 'updated_at',
        ])
    return {**result, 'validation_run_id': str(run.id), 'evidence_id': str(evidence.id)}
