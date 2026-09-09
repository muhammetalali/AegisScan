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
    """Map explicit browser security violations to stable semantic findings.

    Informational browser characteristics (third-party hosts, iframe counts,
    inline scripts, and password-field presence alone) remain Evidence only.
    Findings are emitted only for observations that directly demonstrate a
    transport downgrade or cleartext form submission path.
    """
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


def _finding_id(scan_id: str, capability_id: str, rule_id: str) -> UUID:
    key = ':'.join((str(scan_id).lower(), capability_id.strip().lower(), rule_id.strip().lower()))
    return uuid5(FINDING_NAMESPACE, key)


def project_native_findings(
    *,
    scan: Any,
    capability_id: str,
    source_engine: str,
    target: str,
    normalized: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Persist idempotent semantic findings and finding-linked evidence."""
    if capability_id != 'browser.dom-snapshot':
        return [], []

    from django_project.evidence.models import Evidence
    from django_project.vulnerabilities.models import Vulnerability

    finding_ids: list[str] = []
    evidence_ids: list[str] = []
    for spec in browser_finding_specs(normalized):
        finding_pk = _finding_id(str(scan.id), capability_id, spec.rule_id)
        finding, _ = Vulnerability.objects.update_or_create(
            id=finding_pk,
            defaults={
                'scan': scan,
                'project': scan.project,
                'asset': scan.asset,
                'title': spec.title,
                'description': spec.description,
                'severity': spec.severity,
                'status': Vulnerability.Status.OPEN,
                'confidence': spec.confidence,
                'category': spec.category,
                'cwe_id': spec.cwe_id,
                'owasp_category': spec.owasp_category,
                'tags': ['aegisscan-native', 'browser-security', spec.rule_id],
                'url': str(target)[:2000],
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
            },
        )
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
