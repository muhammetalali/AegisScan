from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any
from uuid import UUID, uuid5

from .evidence_identity import evidence_id


FINDING_NAMESPACE = UUID('3ed142e9-1b4f-4e96-bf4f-6d14b3421f50')


@dataclass(frozen=True)
class NativeFindingSpec:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    cwe_id: str = ''
    owasp_category: str = ''
    remediation: str = ''
    affected_urls: tuple[str, ...] = ()
    raw_data: dict[str, Any] | None = None
    identity_key: str = ''


def _bounded_urls(values: Any, limit: int = 100) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    result: list[str] = []
    for value in values[:limit]:
        candidate = str(value).strip()
        if candidate.startswith(('http://', 'https://')) and len(candidate) <= 2048:
            result.append(candidate)
    return tuple(sorted(set(result)))


def browser_finding_specs(normalized: dict[str, Any]) -> list[NativeFindingSpec]:
    """Map explicit browser security violations to stable semantic findings."""
    observations = normalized.get('observations') if isinstance(normalized, dict) else None
    if not isinstance(observations, list):
        return []

    mixed: set[str] = set()
    insecure_forms: set[str] = set()
    password_fields = 0
    for observation in observations:
        if not isinstance(observation, dict) or observation.get('kind') != 'browser-dom-security-snapshot':
            continue
        mixed.update(_bounded_urls(observation.get('mixed_content_urls')))
        insecure_forms.update(_bounded_urls(observation.get('insecure_form_actions')))
        try:
            password_fields = max(password_fields, int(observation.get('password_field_count') or 0))
        except (TypeError, ValueError):
            pass

    findings: list[NativeFindingSpec] = []
    if mixed:
        affected = tuple(sorted(mixed))[:100]
        findings.append(NativeFindingSpec(
            rule_id='browser.mixed-content',
            title='Mixed content loaded by HTTPS page',
            description=(
                'The rendered page references one or more HTTP resources from an HTTPS context, '
                'creating a transport downgrade that can weaken confidentiality and integrity.'
            ),
            severity='medium',
            confidence='high',
            category='browser-security',
            cwe_id='CWE-319',
            owasp_category='A02:2021-Cryptographic Failures',
            remediation='Serve every page resource over HTTPS and remove or upgrade all HTTP references.',
            affected_urls=affected,
            raw_data={'affected_urls': list(affected)},
        ))

    if insecure_forms:
        affected = tuple(sorted(insecure_forms))[:100]
        carries_password = password_fields > 0
        findings.append(NativeFindingSpec(
            rule_id='browser.insecure-form-action',
            title='Form submits data over cleartext HTTP',
            description=(
                'A rendered form submits to an HTTP endpoint. '
                + ('The page also contains password input fields, increasing credential exposure risk.' if carries_password else 'Submitted form data can be exposed or modified in transit.')
            ),
            severity='high' if carries_password else 'medium',
            confidence='high',
            category='browser-security',
            cwe_id='CWE-319',
            owasp_category='A02:2021-Cryptographic Failures',
            remediation='Submit forms only to HTTPS endpoints and enforce HTTPS redirects/HSTS at the application edge.',
            affected_urls=affected,
            raw_data={'affected_urls': list(affected), 'password_fields_present': carries_password},
        ))
    return findings


def _api_finding_specs(
    normalized: dict[str, Any],
    *,
    observation_kind: str,
    category: str,
) -> list[NativeFindingSpec]:
    observations = normalized.get('observations') if isinstance(normalized, dict) else None
    if not isinstance(observations, list):
        return []
    findings: list[NativeFindingSpec] = []
    severities = {'critical', 'high', 'medium', 'low', 'info'}
    confidences = {'high', 'medium', 'low'}
    for observation in observations[:2000]:
        if not isinstance(observation, dict) or observation.get('kind') != observation_kind:
            continue
        rule_id = str(observation.get('rule_id') or '').strip()[:200]
        title = str(observation.get('title') or '').strip()[:500]
        description = str(observation.get('description') or '').strip()[:5000]
        remediation = str(observation.get('remediation') or '').strip()[:5000]
        severity = str(observation.get('severity') or 'info').lower()
        confidence = str(observation.get('confidence') or 'medium').lower()
        if not rule_id or not title or not description or severity not in severities or confidence not in confidences:
            continue
        location = str(observation.get('location') or '').strip()[:2048]
        method = str(observation.get('method') or '').strip().upper()[:16]
        path = str(observation.get('path') or '').strip()[:2048]
        parameter = str(observation.get('parameter') or '').strip()[:200]
        identity = '|'.join((rule_id, location, method, path, parameter))
        validation_errors = observation.get('validation_errors')
        safe_errors = (
            [str(value)[:500] for value in validation_errors[:20]]
            if isinstance(validation_errors, list)
            else []
        )
        raw_data: dict[str, Any] = {
            'location': location,
            'method': method,
            'path': path,
            'parameter': parameter,
        }
        try:
            if observation.get('status') is not None:
                raw_data['status'] = int(observation.get('status'))
        except (TypeError, ValueError):
            pass
        if safe_errors:
            raw_data['validation_errors'] = safe_errors
        findings.append(NativeFindingSpec(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            category=category,
            cwe_id=str(observation.get('cwe_id') or '')[:64],
            owasp_category=str(observation.get('owasp_category') or '')[:200],
            remediation=remediation,
            affected_urls=_bounded_urls(observation.get('affected_urls'), 20),
            raw_data=raw_data,
            identity_key=identity,
        ))
    return findings


def api_schema_finding_specs(normalized: dict[str, Any]) -> list[NativeFindingSpec]:
    """Project explicit security findings emitted by the defensive schema analyzer."""
    return _api_finding_specs(
        normalized,
        observation_kind='api-schema-security-finding',
        category='api-security',
    )


def api_runtime_finding_specs(normalized: dict[str, Any]) -> list[NativeFindingSpec]:
    """Project explicit runtime contract violations from safe authorized API probes."""
    return _api_finding_specs(
        normalized,
        observation_kind='api-runtime-security-finding',
        category='api-runtime-security',
    )


def _finding_id(scan_id: str, capability_id: str, spec: NativeFindingSpec) -> UUID:
    identity = spec.identity_key or spec.rule_id
    key = ':'.join((str(scan_id).lower(), capability_id.strip().lower(), identity.strip().lower()))
    return uuid5(FINDING_NAMESPACE, key)


def _technical_defaults(scan: Any, capability_id: str, source_engine: str, target: str, spec: NativeFindingSpec) -> dict[str, Any]:
    return {
        'scan': scan,
        'project': scan.project,
        'asset': scan.asset,
        'title': spec.title,
        'description': spec.description,
        'severity': spec.severity,
        'confidence': spec.confidence,
        'category': spec.category,
        'cwe_id': spec.cwe_id,
        'owasp_category': spec.owasp_category,
        'tags': ['aegisscan-native', spec.category, spec.rule_id],
        'url': str(target)[:200],
        'risk_score': {'critical': 9.5, 'high': 8.0, 'medium': 5.0, 'low': 2.0, 'info': 0.5}.get(spec.severity, 0.0),
        'evidence_count': 1,
        'remediation': spec.remediation,
        'fix_available': True,
        'source_engine': source_engine,
        'raw_data': {
            'schema': 'aegis.native-finding.v1',
            'capability_id': capability_id,
            'rule_id': spec.rule_id,
            **(spec.raw_data or {}),
        },
    }


def project_native_findings(
    *,
    scan: Any,
    capability_id: str,
    source_engine: str,
    target: str,
    normalized: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Persist idempotent semantic findings and finding-linked evidence.

    Redelivery updates technical evidence but deliberately preserves workflow
    state such as status, assignee, accepted-risk decisions, validation data,
    and remediation tracking already governed by users or later workflows.
    """
    if capability_id == 'browser.dom-snapshot':
        specs = browser_finding_specs(normalized)
    elif capability_id == 'api.openapi-contract-security':
        specs = api_schema_finding_specs(normalized)
    elif capability_id == 'api.openapi-runtime-conformance':
        specs = api_runtime_finding_specs(normalized)
    else:
        return [], []

    from django_project.evidence.models import Evidence
    from django_project.vulnerabilities.models import Vulnerability

    finding_ids: list[str] = []
    evidence_ids: list[str] = []
    for spec in specs:
        finding_pk = _finding_id(str(scan.id), capability_id, spec)
        technical = _technical_defaults(scan, capability_id, source_engine, target, spec)
        create_defaults = {**technical, 'status': Vulnerability.Status.OPEN}
        finding, created = Vulnerability.objects.get_or_create(id=finding_pk, defaults=create_defaults)
        if not created:
            for field, value in technical.items():
                setattr(finding, field, value)
            finding.save(update_fields=[*technical.keys(), 'last_seen', 'updated_at'])

        evidence_payload = {
            'schema': 'aegis.native-finding-evidence.v1',
            'capability_id': capability_id,
            'rule_id': spec.rule_id,
            'finding': asdict(spec),
        }
        finding_evidence, _ = Evidence.objects.update_or_create(
            id=evidence_id('scan', str(scan.id), source_engine, 'finding_observation', str(finding.id)),
            defaults={
                'scan': scan,
                'asset': scan.asset,
                'finding': finding,
                'source': source_engine,
                'evidence_type': 'finding_observation',
                'raw_output': json.dumps(evidence_payload, sort_keys=True, separators=(',', ':')),
                'metadata': {
                    'capability_id': capability_id,
                    'rule_id': spec.rule_id,
                    'target': str(target),
                    'semantic_projection': True,
                },
                'collected_by': scan.initiated_by,
            },
        )
        finding_ids.append(str(finding.id))
        evidence_ids.append(str(finding_evidence.id))
    return finding_ids, evidence_ids


def sync_scan_finding_counts(scan: Any) -> None:
    """Recompute scan counters from persisted findings; never increment blindly."""
    from django_project.vulnerabilities.models import Vulnerability

    counts = {severity: 0 for severity in ('critical', 'high', 'medium', 'low', 'info')}
    for row in Vulnerability.objects.filter(scan=scan).values('severity'):
        severity = str(row.get('severity') or '')
        if severity in counts:
            counts[severity] += 1
    scan.findings_count = sum(counts.values())
    scan.critical_count = counts['critical']
    scan.high_count = counts['high']
    scan.medium_count = counts['medium']
    scan.low_count = counts['low']
    scan.info_count = counts['info']
