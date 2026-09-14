from __future__ import annotations

from collections import Counter
from datetime import timezone
from typing import Any

from django.db.models import Q

from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability

from .capability_registry import get_capability
from .wstg_catalog import WSTGCatalog
from .wstg_observation_lineage import wstg_observation_lineage


OBSERVATION_ONLY_POLICY = 'observation-only'
COMPLETION_CLAIM_ALLOWED = False
FINDING_STATE_AUTHORITY = 'governed-finding-confirmation'

_CLASSIFICATION_STATE = {
    'AUTO_EXISTING': 'not_observed',
    'ASSISTED_EXISTING': 'not_observed',
    'MANUAL_GOVERNED': 'manual_required',
    'GAP_NATIVE_SMALL': 'blocked_native_gap',
    'CONDITIONAL_NA': 'inconclusive',
}


def _iso(value) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _trusted_lineage(value: Any, *, expected_source: str | None = None) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    capability_id = value.get('capability_id')
    if not isinstance(capability_id, str) or not capability_id:
        return None
    try:
        capability = get_capability(capability_id)
        canonical = wstg_observation_lineage(capability_id)
    except (KeyError, ValueError):
        return None
    if expected_source is not None and str(expected_source).strip().lower() != capability.tool.strip().lower():
        return None
    if (
        value.get('schema') != canonical['schema']
        or value.get('methodology') != 'WSTG'
        or value.get('methodology_version') != '4.2'
        or value.get('claim_policy') != OBSERVATION_ONLY_POLICY
        or value.get('completion_claim_allowed') is not False
        or value.get('finding_state_authority') != FINDING_STATE_AUTHORITY
        or value.get('lineage_fingerprint') != canonical['lineage_fingerprint']
        or value.get('tests') != canonical['tests']
    ):
        return None
    return canonical


def _project_evidence(project: Project, scan_id: str | None):
    qs = Evidence.objects.filter(
        Q(scan__project=project) | Q(finding__project=project) | Q(asset__project=project)
    ).distinct()
    if scan_id:
        qs = qs.filter(scan_id=scan_id)
    return qs.only('id', 'source', 'metadata', 'collected_at')


def _project_findings(project: Project, scan_id: str | None):
    qs = Vulnerability.objects.filter(project=project)
    if scan_id:
        qs = qs.filter(scan_id=scan_id)
    return qs.only('id', 'source_engine', 'raw_data', 'updated_at')


def build_wstg_project_coverage(project: Project, *, scan_id: str | None = None) -> dict[str, Any]:
    catalog = WSTGCatalog()
    rows: dict[str, dict[str, Any]] = {}
    for test in catalog.tests:
        rows[test.id] = {
            'wstg_id': test.id,
            'category': test.category,
            'title': test.title,
            'classification': test.classification,
            'state': _CLASSIFICATION_STATE[test.classification],
            'has_observation': False,
            'evidence_records': 0,
            'finding_records': 0,
            'capability_ids': set(),
            'latest_observed_at': None,
            'completion_claim_allowed': False,
        }

    trusted_evidence_records = 0
    trusted_finding_records = 0
    rejected_lineage_records = 0

    for evidence in _project_evidence(project, scan_id):
        metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
        raw = metadata.get('wstg_lineage')
        if raw is None:
            continue
        lineage = _trusted_lineage(raw, expected_source=evidence.source)
        if lineage is None:
            rejected_lineage_records += 1
            continue
        trusted_evidence_records += 1
        for item in lineage['tests']:
            row = rows.get(item['wstg_id'])
            if row is None:
                rejected_lineage_records += 1
                continue
            row['evidence_records'] += 1
            row['capability_ids'].add(lineage['capability_id'])
            observed_at = evidence.collected_at
            if row['latest_observed_at'] is None or observed_at > row['latest_observed_at']:
                row['latest_observed_at'] = observed_at

    for finding in _project_findings(project, scan_id):
        raw_data = finding.raw_data if isinstance(finding.raw_data, dict) else {}
        raw = raw_data.get('_aegisscan_wstg')
        if raw is None:
            continue
        lineage = _trusted_lineage(raw, expected_source=finding.source_engine)
        if lineage is None:
            rejected_lineage_records += 1
            continue
        trusted_finding_records += 1
        for item in lineage['tests']:
            row = rows.get(item['wstg_id'])
            if row is None:
                rejected_lineage_records += 1
                continue
            row['finding_records'] += 1
            row['capability_ids'].add(lineage['capability_id'])
            observed_at = finding.updated_at
            if row['latest_observed_at'] is None or observed_at > row['latest_observed_at']:
                row['latest_observed_at'] = observed_at

    ordered = []
    for test in catalog.tests:
        row = rows[test.id]
        observed = (row['evidence_records'] + row['finding_records']) > 0
        row['has_observation'] = observed
        if observed and test.classification in {'AUTO_EXISTING', 'ASSISTED_EXISTING'}:
            row['state'] = 'observed'
        row['capability_ids'] = sorted(row['capability_ids'])
        row['latest_observed_at'] = _iso(row['latest_observed_at'])
        ordered.append(row)

    observed_tests = sum(1 for row in ordered if row['has_observation'])
    auto_assisted = [row for row in ordered if row['classification'] in {'AUTO_EXISTING', 'ASSISTED_EXISTING'}]
    auto_assisted_observed = sum(1 for row in auto_assisted if row['has_observation'])

    category_summary: dict[str, dict[str, Any]] = {}
    for category in sorted({row['category'] for row in ordered}):
        category_rows = [row for row in ordered if row['category'] == category]
        observed = sum(1 for row in category_rows if row['has_observation'])
        category_summary[category] = {
            'total': len(category_rows),
            'observed': observed,
            'observation_coverage_percent': round((observed / len(category_rows)) * 100, 2),
        }

    classification_summary: dict[str, dict[str, Any]] = {}
    for classification in sorted({row['classification'] for row in ordered}):
        class_rows = [row for row in ordered if row['classification'] == classification]
        observed = sum(1 for row in class_rows if row['has_observation'])
        classification_summary[classification] = {
            'total': len(class_rows),
            'observed': observed,
            'observation_coverage_percent': round((observed / len(class_rows)) * 100, 2),
        }

    states = Counter(row['state'] for row in ordered)
    return {
        'contract_version': '1.0',
        'methodology': 'WSTG',
        'methodology_version': '4.2',
        'source': 'postgresql',
        'project_id': str(project.id),
        'project_name': project.name,
        'scope_scan_id': str(scan_id) if scan_id else None,
        'claim_policy': OBSERVATION_ONLY_POLICY,
        'completion_claim_allowed': COMPLETION_CLAIM_ALLOWED,
        'finding_state_authority': FINDING_STATE_AUTHORITY,
        'summary': {
            'total_tests': len(ordered),
            'observed_tests': observed_tests,
            'observation_coverage_percent': round((observed_tests / len(ordered)) * 100, 2),
            'auto_assisted_total': len(auto_assisted),
            'auto_assisted_observed': auto_assisted_observed,
            'auto_assisted_observation_coverage_percent': round(
                (auto_assisted_observed / len(auto_assisted)) * 100, 2
            ),
            'trusted_evidence_records': trusted_evidence_records,
            'trusted_finding_records': trusted_finding_records,
            'rejected_lineage_records': rejected_lineage_records,
            'states': dict(sorted(states.items())),
        },
        'category_summary': category_summary,
        'classification_summary': classification_summary,
        'tests': ordered,
    }
