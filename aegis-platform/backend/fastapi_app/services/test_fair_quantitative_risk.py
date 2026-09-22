from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from enterprise.fair_risk_models import FAIRQuantitativeRiskAnalysis
from enterprise.models import OrganizationMembership, TenantProject
from fastapi_app.services.fair_quantitative_risk import (
    FAIRRiskAuthorizationError,
    FAIRRiskError,
    FAIR_FACTOR_KEYS,
    analyze_fair_risk,
    simulate_fair_distribution,
)
from fastapi_app.services.risk_correlation import correlate_finding
from enterprise.test_risk_correlation import correlation_context  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)


def _bind_tenant(correlation_context):
    user, project, _asset, _scan, _finding, _intel, _snapshot, path = correlation_context
    organization = path.organization
    TenantProject.objects.get_or_create(organization=organization, project=project)
    OrganizationMembership.objects.get_or_create(
        organization=organization,
        user=user,
        defaults={'role': OrganizationMembership.Role.OWNER, 'is_active': True},
    )
    return user, project, organization


def _assumptions():
    return {
        'threat_event_frequency': {'low': 2.0, 'mode': 6.0, 'high': 12.0},
        'vulnerability': {'low': 0.10, 'mode': 0.35, 'high': 0.70},
        'primary_loss_magnitude': {'low': 10000.0, 'mode': 50000.0, 'high': 150000.0},
        'secondary_event_probability': {'low': 0.05, 'mode': 0.15, 'high': 0.40},
        'secondary_loss_magnitude': {'low': 5000.0, 'mode': 25000.0, 'high': 90000.0},
    }


def _context(correlation_context):
    user, project, _organization = _bind_tenant(correlation_context)
    _u, _p, asset, scan, finding, *_rest = correlation_context
    correlation, created = correlate_finding(finding, actor_id=str(user.id))
    assert created is True
    evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=finding,
        source='fair-input',
        evidence_type='risk_input',
        raw_output='evidence-backed quantitative risk input',
        metadata={'fair_factors': list(FAIR_FACTOR_KEYS)},
        collected_by=user,
    )
    evidence_map = {factor: [str(evidence.id)] for factor in FAIR_FACTOR_KEYS}
    return user, project, finding, correlation, evidence, evidence_map


def test_fair_simulation_is_seed_deterministic_and_percentiles_are_ordered():
    assumptions = _assumptions()
    first = simulate_fair_distribution(assumptions=assumptions, iterations=2000, seed=4242, currency='USD')
    second = simulate_fair_distribution(assumptions=assumptions, iterations=2000, seed=4242, currency='USD')
    different = simulate_fair_distribution(assumptions=assumptions, iterations=2000, seed=4243, currency='USD')

    assert first == second
    assert first != different
    annual = first['annualized_loss_exposure']
    assert float(annual['p05']) <= float(annual['p50']) <= float(annual['p90']) <= float(annual['p95']) <= float(annual['max'])
    assert first['iterations'] == 2000
    assert first['seed'] == 4242


def test_fair_analysis_is_immutable_evidence_linked_and_replay_safe(correlation_context):
    user, project, finding, correlation, evidence, evidence_map = _context(correlation_context)
    first = analyze_fair_risk(
        project_id=str(project.id),
        risk_correlation_id=str(correlation.id),
        actor_id=str(user.id),
        assumptions=_assumptions(),
        assumption_evidence=evidence_map,
        iterations=2000,
        seed=99,
        currency='USD',
    )
    second = analyze_fair_risk(
        project_id=str(project.id),
        risk_correlation_id=str(correlation.id),
        actor_id=str(user.id),
        assumptions=_assumptions(),
        assumption_evidence=evidence_map,
        iterations=2000,
        seed=99,
        currency='USD',
    )

    assert first.replayed is False
    assert second.replayed is True
    assert second.analysis.id == first.analysis.id
    row = first.analysis
    assert row.project_id == project.id
    assert row.vulnerability_id == finding.id
    assert row.risk_correlation_id == correlation.id
    assert row.analysis_version == 1
    assert row.simulation_iterations == 2000
    assert row.simulation_seed == 99
    assert len(row.assumptions_sha256) == 64
    assert len(row.evidence_sha256) == 64
    assert len(row.result_sha256) == 64
    assert row.evidence_snapshot[0]['evidence_id'] == str(evidence.id)
    assert set(row.evidence_snapshot[0]['supports']) == set(FAIR_FACTOR_KEYS)
    assert row.result_summary['lineage']['risk_correlation_sha256'] == correlation.correlation_sha256
    assert row.annual_loss_p50 <= row.annual_loss_p95

    with pytest.raises(ValidationError, match='immutable'):
        FAIRQuantitativeRiskAnalysis.objects.filter(pk=row.id).update(currency='EUR')
    with pytest.raises(ValidationError, match='immutable'):
        row.delete()


def test_fair_rejects_unsupported_or_unproven_assumptions(correlation_context):
    user, project, _finding, correlation, _evidence, evidence_map = _context(correlation_context)
    incomplete = dict(evidence_map)
    incomplete['primary_loss_magnitude'] = []
    with pytest.raises(FAIRRiskError, match='primary_loss_magnitude'):
        analyze_fair_risk(
            project_id=str(project.id),
            risk_correlation_id=str(correlation.id),
            actor_id=str(user.id),
            assumptions=_assumptions(),
            assumption_evidence=incomplete,
            iterations=1000,
            seed=1,
        )

    bad = _assumptions()
    bad['vulnerability'] = {'low': 0.2, 'mode': 0.8, 'high': 1.2}
    with pytest.raises(FAIRRiskError, match='0..1'):
        analyze_fair_risk(
            project_id=str(project.id),
            risk_correlation_id=str(correlation.id),
            actor_id=str(user.id),
            assumptions=bad,
            assumption_evidence=evidence_map,
            iterations=1000,
            seed=1,
        )


def test_fair_rejects_stale_risk_correlation(correlation_context):
    user, project, finding, correlation, _evidence, evidence_map = _context(correlation_context)
    Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source='validation',
        evidence_type='validation_output',
        raw_output='newer independent evidence',
        metadata={'finding_present': True},
        collected_by=user,
    )
    newer, created = correlate_finding(finding, actor_id=str(user.id))
    assert created is True
    assert newer.id != correlation.id

    with pytest.raises(FAIRRiskAuthorizationError, match='latest risk correlation'):
        analyze_fair_risk(
            project_id=str(project.id),
            risk_correlation_id=str(correlation.id),
            actor_id=str(user.id),
            assumptions=_assumptions(),
            assumption_evidence=evidence_map,
            iterations=1000,
            seed=1,
        )


def test_fair_rejects_cross_project_evidence(correlation_context):
    user, project, _finding, correlation, _evidence, evidence_map = _context(correlation_context)
    other = Project.objects.create(name='FAIR other project', slug='fair-other-project', owner=user)
    foreign = Evidence.objects.create(
        source='fair-input',
        evidence_type='risk_input',
        raw_output='foreign project evidence cannot support this analysis',
        collected_by=user,
    )
    # Deliberately no project lineage at all; fail closed rather than treating it as global evidence.
    mixed = dict(evidence_map)
    mixed['secondary_loss_magnitude'] = [str(foreign.id)]
    with pytest.raises(FAIRRiskAuthorizationError, match='requested project'):
        analyze_fair_risk(
            project_id=str(project.id),
            risk_correlation_id=str(correlation.id),
            actor_id=str(user.id),
            assumptions=_assumptions(),
            assumption_evidence=mixed,
            iterations=1000,
            seed=1,
        )
    assert other.id != project.id


def test_fair_rejects_evidence_integrity_drift(correlation_context):
    user, project, _finding, correlation, evidence, evidence_map = _context(correlation_context)
    Evidence.objects.filter(pk=evidence.id).update(raw_output='tampered without digest refresh')
    with pytest.raises(FAIRRiskError, match='integrity mismatch'):
        analyze_fair_risk(
            project_id=str(project.id),
            risk_correlation_id=str(correlation.id),
            actor_id=str(user.id),
            assumptions=_assumptions(),
            assumption_evidence=evidence_map,
            iterations=1000,
            seed=1,
        )


def test_fair_routes_are_wired(correlation_context):
    _bind_tenant(correlation_context)
    from fastapi_app.main import app

    paths = set(app.openapi().get('paths', {}))
    assert '/api/v1/fair-risk/projects/{project_id}/analyses' in paths
    assert '/api/v1/fair-risk/analyses/{analysis_id}' in paths
