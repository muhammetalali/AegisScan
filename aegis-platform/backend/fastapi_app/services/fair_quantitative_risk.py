from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from statistics import fmean
from typing import Any

from django.db import transaction

from django_project.evidence.models import Evidence
from django_project.projects.models import Project, ProjectMembership
from enterprise.fair_risk_models import FAIRQuantitativeRiskAnalysis
from enterprise.models import Organization, OrganizationMembership, RiskCorrelationSnapshot, TenantProject

from .audit_writer import add_audit_entry


FAIR_POLICY_VERSION = 'fair-quantitative-risk.v1'
FAIR_FACTOR_KEYS = (
    'threat_event_frequency',
    'vulnerability',
    'primary_loss_magnitude',
    'secondary_event_probability',
    'secondary_loss_magnitude',
)
_MIN_ITERATIONS = 1000
_MAX_ITERATIONS = 50000
_MAX_SEED = 9223372036854775807


class FAIRRiskError(ValueError):
    pass


class FAIRRiskAuthorizationError(FAIRRiskError):
    pass


@dataclass(frozen=True)
class FAIRRiskResult:
    analysis: FAIRQuantitativeRiskAnalysis
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _money(value: float) -> Decimal:
    return Decimal(str(max(0.0, float(value)))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _estimate(
    value: Any, *, factor: str, probability: bool = False, maximum: float = 1_000_000_000_000_000
) -> dict[str, float]:
    if not isinstance(value, dict):
        raise FAIRRiskError(f'{factor} must be a three-point estimate object.')
    try:
        low = float(value['low'])
        mode = float(value['mode'])
        high = float(value['high'])
    except (KeyError, TypeError, ValueError) as exc:
        raise FAIRRiskError(f'{factor} requires numeric low, mode, and high values.') from exc
    if not all(math.isfinite(v) for v in (low, mode, high)):
        raise FAIRRiskError(f'{factor} contains a non-finite value.')
    if low < 0 or low > mode or mode > high:
        raise FAIRRiskError(f'{factor} must satisfy 0 <= low <= mode <= high.')
    if probability and high > 1.0:
        raise FAIRRiskError(f'{factor} must stay within the 0..1 probability range.')
    if not probability and high > maximum:
        raise FAIRRiskError(f'{factor} exceeds the supported upper bound.')
    return {'low': low, 'mode': mode, 'high': high}


def normalize_assumptions(assumptions: dict[str, Any]) -> dict[str, dict[str, float]]:
    if not isinstance(assumptions, dict):
        raise FAIRRiskError('assumptions must be an object.')
    unknown = sorted(set(assumptions) - set(FAIR_FACTOR_KEYS))
    missing = sorted(set(FAIR_FACTOR_KEYS) - set(assumptions))
    if unknown:
        raise FAIRRiskError(f'Unsupported FAIR assumptions: {unknown}.')
    if missing:
        raise FAIRRiskError(f'Missing FAIR assumptions: {missing}.')
    return {
        'threat_event_frequency': _estimate(
            assumptions['threat_event_frequency'], factor='threat_event_frequency', maximum=1_000_000
        ),
        'vulnerability': _estimate(assumptions['vulnerability'], factor='vulnerability', probability=True),
        'primary_loss_magnitude': _estimate(assumptions['primary_loss_magnitude'], factor='primary_loss_magnitude'),
        'secondary_event_probability': _estimate(
            assumptions['secondary_event_probability'], factor='secondary_event_probability', probability=True
        ),
        'secondary_loss_magnitude': _estimate(
            assumptions['secondary_loss_magnitude'], factor='secondary_loss_magnitude'
        ),
    }


def normalize_evidence_map(value: dict[str, Any]) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise FAIRRiskError('assumption_evidence must be an object.')
    unknown = sorted(set(value) - set(FAIR_FACTOR_KEYS))
    missing = sorted(set(FAIR_FACTOR_KEYS) - set(value))
    if unknown:
        raise FAIRRiskError(f'Unsupported FAIR evidence factors: {unknown}.')
    if missing:
        raise FAIRRiskError(f'Missing FAIR evidence mappings: {missing}.')
    normalized: dict[str, list[str]] = {}
    for factor in FAIR_FACTOR_KEYS:
        rows = value.get(factor)
        if not isinstance(rows, list) or not rows:
            raise FAIRRiskError(f'{factor} must reference at least one evidence record.')
        ids = sorted({str(item).strip() for item in rows if str(item).strip()})
        if not ids:
            raise FAIRRiskError(f'{factor} must reference at least one evidence record.')
        normalized[factor] = ids
    return normalized


def _project_ids(evidence: Evidence) -> set[str]:
    values: set[str] = set()
    if evidence.scan_id and evidence.scan is not None:
        values.add(str(evidence.scan.project_id))
    if evidence.asset_id and evidence.asset is not None:
        values.add(str(evidence.asset.project_id))
    if evidence.finding_id and evidence.finding is not None:
        values.add(str(evidence.finding.project_id))
    return values


def _active_context(*, project_id: str, risk_correlation_id: str, actor_id: str):
    link_identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if link_identity is None:
        raise FAIRRiskAuthorizationError('Project is not bound to an active enterprise tenant.')

    organization = Organization.objects.select_for_update().filter(
        pk=link_identity['organization_id'], is_active=True
    ).first()
    if organization is None:
        raise FAIRRiskAuthorizationError('Enterprise tenant is inactive.')

    link = TenantProject.objects.select_for_update(of=('self',)).filter(
        pk=link_identity['id'], organization=organization, project_id=project_id
    ).first()
    if link is None:
        raise FAIRRiskAuthorizationError('Tenant/project binding changed before FAIR analysis.')

    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None:
        raise FAIRRiskAuthorizationError('Project was not found.')

    project_allowed = str(project.owner_id) == str(actor_id) or ProjectMembership.objects.filter(
        project=project,
        user_id=actor_id,
        role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN, ProjectMembership.Role.MEMBER],
    ).exists()
    if not project_allowed:
        raise FAIRRiskAuthorizationError('Actor has no project access.')
    if not OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
        role__in=[
            OrganizationMembership.Role.OWNER,
            OrganizationMembership.Role.ADMIN,
            OrganizationMembership.Role.MANAGER,
            OrganizationMembership.Role.ANALYST,
        ],
    ).exists():
        raise FAIRRiskAuthorizationError('Actor has no active enterprise risk-analysis role.')

    correlation = (
        RiskCorrelationSnapshot.objects.select_for_update()
        .select_related('vulnerability', 'finding_intelligence', 'source_snapshot')
        .filter(pk=risk_correlation_id, project=project)
        .first()
    )
    if correlation is None:
        raise FAIRRiskAuthorizationError('Risk correlation snapshot was not found in the requested project.')
    latest = (
        RiskCorrelationSnapshot.objects.select_for_update()
        .filter(project=project, vulnerability_id=correlation.vulnerability_id)
        .order_by('-created_at', '-id')
        .first()
    )
    if latest is None or latest.id != correlation.id:
        raise FAIRRiskAuthorizationError('FAIR analysis requires the latest risk correlation snapshot for the finding.')
    if len(str(correlation.correlation_sha256 or '')) != 64:
        raise FAIRRiskError('Risk correlation integrity digest is missing or invalid.')
    if (
        correlation.source_snapshot is None
        or correlation.source_snapshot_sha256 != correlation.source_snapshot.snapshot_sha256
    ):
        raise FAIRRiskError('Risk correlation intelligence lineage integrity mismatch.')
    return organization, project, correlation


def _evidence_snapshot(
    *, project: Project, finding_id: str, asset_id: str, scan_id: str, evidence_map: dict[str, list[str]]
) -> tuple[list[dict[str, Any]], str]:
    requested = sorted({item for values in evidence_map.values() for item in values})
    rows = list(
        Evidence.objects.select_for_update(of=('self',))
        .select_related('scan', 'asset', 'finding')
        .filter(pk__in=requested)
    )
    by_id = {str(row.id): row for row in rows}
    if set(by_id) != set(requested):
        raise FAIRRiskError('One or more FAIR evidence references do not exist.')

    reverse: dict[str, list[str]] = {evidence_id: [] for evidence_id in requested}
    for factor, ids in evidence_map.items():
        for evidence_id in ids:
            reverse[evidence_id].append(factor)

    snapshot: list[dict[str, Any]] = []
    for evidence_id in requested:
        row = by_id[evidence_id]
        project_ids = _project_ids(row)
        if project_ids != {str(project.id)}:
            raise FAIRRiskAuthorizationError('FAIR evidence must resolve exclusively to the requested project.')
        subject_matches = (
            str(row.finding_id or '') == str(finding_id)
            or (asset_id and str(row.asset_id or '') == str(asset_id))
            or (scan_id and str(row.scan_id or '') == str(scan_id))
        )
        if not subject_matches:
            raise FAIRRiskAuthorizationError('FAIR evidence is not bound to the analyzed finding, asset, or scan.')
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        declared = {str(item) for item in metadata.get('fair_factors', []) if str(item)}
        mapped = set(reverse[evidence_id])
        if not mapped <= declared:
            raise FAIRRiskError(f'FAIR evidence {row.id} does not explicitly support every mapped assumption.')
        computed = hashlib.sha256((row.raw_output or '').encode('utf-8', errors='replace')).hexdigest()
        if not row.sha256 or computed != row.sha256:
            raise FAIRRiskError(f'FAIR evidence integrity mismatch for {row.id}.')
        snapshot.append({
            'evidence_id': str(row.id),
            'sha256': row.sha256,
            'source': str(row.source),
            'evidence_type': str(row.evidence_type),
            'collected_at': row.collected_at.isoformat() if row.collected_at else '',
            'supports': sorted(reverse[evidence_id]),
        })
    snapshot.sort(key=lambda item: item['evidence_id'])
    return snapshot, _sha(snapshot)


def simulate_fair_distribution(
    *, assumptions: dict[str, dict[str, float]], iterations: int, seed: int, currency: str
) -> dict[str, Any]:
    if not (_MIN_ITERATIONS <= int(iterations) <= _MAX_ITERATIONS):
        raise FAIRRiskError(f'iterations must be between {_MIN_ITERATIONS} and {_MAX_ITERATIONS}.')
    if int(seed) < 0 or int(seed) > _MAX_SEED:
        raise FAIRRiskError('seed is outside the supported deterministic range.')
    currency = str(currency or '').strip().upper()
    if len(currency) != 3 or not currency.isalpha():
        raise FAIRRiskError('currency must be a three-letter alphabetic code.')

    rng = random.Random(int(seed))
    lef_values: list[float] = []
    loss_magnitude_values: list[float] = []
    annual_loss_values: list[float] = []

    for _ in range(int(iterations)):
        tef_est = assumptions['threat_event_frequency']
        vuln_est = assumptions['vulnerability']
        primary_est = assumptions['primary_loss_magnitude']
        secondary_probability_est = assumptions['secondary_event_probability']
        secondary_loss_est = assumptions['secondary_loss_magnitude']

        tef = rng.triangular(tef_est['low'], tef_est['high'], tef_est['mode'])
        vulnerability = rng.triangular(vuln_est['low'], vuln_est['high'], vuln_est['mode'])
        primary_loss = rng.triangular(primary_est['low'], primary_est['high'], primary_est['mode'])
        secondary_probability = rng.triangular(
            secondary_probability_est['low'], secondary_probability_est['high'], secondary_probability_est['mode']
        )
        secondary_loss = rng.triangular(
            secondary_loss_est['low'], secondary_loss_est['high'], secondary_loss_est['mode']
        )

        loss_event_frequency = max(0.0, tef * min(1.0, max(0.0, vulnerability)))
        loss_magnitude = max(0.0, primary_loss + min(1.0, max(0.0, secondary_probability)) * secondary_loss)
        annual_loss = loss_event_frequency * loss_magnitude
        lef_values.append(loss_event_frequency)
        loss_magnitude_values.append(loss_magnitude)
        annual_loss_values.append(annual_loss)

    def stats(values: list[float], *, money: bool = False) -> dict[str, Any]:
        result = {
            'mean': fmean(values),
            'p05': _percentile(values, 0.05),
            'p50': _percentile(values, 0.50),
            'p90': _percentile(values, 0.90),
            'p95': _percentile(values, 0.95),
            'max': max(values),
        }
        if money:
            return {key: str(_money(value)) for key, value in result.items()}
        return {key: round(float(value), 8) for key, value in result.items()}

    return {
        'schema': 'aegis.fair-monte-carlo.v1',
        'policy_version': FAIR_POLICY_VERSION,
        'iterations': int(iterations),
        'seed': int(seed),
        'currency': currency,
        'loss_event_frequency': stats(lef_values),
        'loss_magnitude': stats(loss_magnitude_values, money=True),
        'annualized_loss_exposure': stats(annual_loss_values, money=True),
    }


@transaction.atomic
def analyze_fair_risk(
    *,
    project_id: str,
    risk_correlation_id: str,
    actor_id: str,
    assumptions: dict[str, Any],
    assumption_evidence: dict[str, Any],
    iterations: int = 10000,
    seed: int = 1,
    currency: str = 'USD',
) -> FAIRRiskResult:
    normalized_assumptions = normalize_assumptions(assumptions)
    evidence_map = normalize_evidence_map(assumption_evidence)
    organization, project, correlation = _active_context(
        project_id=str(project_id), risk_correlation_id=str(risk_correlation_id), actor_id=str(actor_id)
    )
    evidence_snapshot, evidence_sha256 = _evidence_snapshot(
        project=project,
        finding_id=str(correlation.vulnerability_id),
        asset_id=str(correlation.vulnerability.asset_id or ''),
        scan_id=str(correlation.vulnerability.scan_id or ''),
        evidence_map=evidence_map,
    )
    assumptions_sha256 = _sha(normalized_assumptions)
    summary = simulate_fair_distribution(
        assumptions=normalized_assumptions,
        iterations=int(iterations),
        seed=int(seed),
        currency=str(currency).upper(),
    )
    lineage = {
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'finding_id': str(correlation.vulnerability_id),
        'risk_correlation_id': str(correlation.id),
        'risk_correlation_sha256': correlation.correlation_sha256,
        'source_snapshot_sha256': correlation.source_snapshot_sha256,
        'assumptions_sha256': assumptions_sha256,
        'evidence_sha256': evidence_sha256,
        'summary': summary,
        'policy_version': FAIR_POLICY_VERSION,
    }
    result_sha256 = _sha(lineage)
    request_fingerprint = _sha({
        'risk_correlation_id': str(correlation.id),
        'assumptions_sha256': assumptions_sha256,
        'evidence_sha256': evidence_sha256,
        'iterations': int(iterations),
        'seed': int(seed),
        'currency': str(currency).upper(),
        'policy_version': FAIR_POLICY_VERSION,
    })

    replay = FAIRQuantitativeRiskAnalysis.objects.filter(request_fingerprint=request_fingerprint).first()
    if replay is not None:
        return FAIRRiskResult(analysis=replay, replayed=True)

    previous = (
        FAIRQuantitativeRiskAnalysis.objects.select_for_update()
        .filter(project=project, vulnerability_id=correlation.vulnerability_id)
        .order_by('-analysis_version', '-created_at', '-id')
        .first()
    )
    next_version = int(previous.analysis_version) + 1 if previous else 1
    annual = summary['annualized_loss_exposure']
    analysis = FAIRQuantitativeRiskAnalysis.objects.create(
        organization=organization,
        project=project,
        vulnerability_id=correlation.vulnerability_id,
        risk_correlation=correlation,
        predecessor=previous,
        analyzed_by_id=actor_id,
        analysis_version=next_version,
        simulation_iterations=int(iterations),
        simulation_seed=int(seed),
        currency=str(currency).upper(),
        assumptions=normalized_assumptions,
        assumption_evidence=evidence_map,
        evidence_snapshot=evidence_snapshot,
        assumptions_sha256=assumptions_sha256,
        evidence_sha256=evidence_sha256,
        loss_event_frequency_mean=float(summary['loss_event_frequency']['mean']),
        annual_loss_mean=Decimal(annual['mean']),
        annual_loss_p50=Decimal(annual['p50']),
        annual_loss_p95=Decimal(annual['p95']),
        result_summary={**summary, 'lineage': {
            'risk_correlation_id': str(correlation.id),
            'risk_correlation_sha256': correlation.correlation_sha256,
            'source_snapshot_id': str(correlation.source_snapshot_id),
            'source_snapshot_sha256': correlation.source_snapshot_sha256,
        }},
        result_sha256=result_sha256,
        request_fingerprint=request_fingerprint,
        policy_version=FAIR_POLICY_VERSION,
    )
    add_audit_entry(
        user=str(actor_id),
        action='fair_risk.analyze',
        target=str(analysis.id),
        project=str(project.id),
        resource_type='fair_quantitative_risk_analysis',
        resource_repr=f'{correlation.vulnerability_id}:v{next_version}',
        metadata={
            'organization_id': str(organization.id),
            'finding_id': str(correlation.vulnerability_id),
            'risk_correlation_id': str(correlation.id),
            'risk_correlation_sha256': correlation.correlation_sha256,
            'assumptions_sha256': assumptions_sha256,
            'evidence_sha256': evidence_sha256,
            'result_sha256': result_sha256,
            'iterations': int(iterations),
            'seed': int(seed),
            'currency': str(currency).upper(),
            'policy_version': FAIR_POLICY_VERSION,
        },
    )
    return FAIRRiskResult(analysis=analysis, replayed=False)
