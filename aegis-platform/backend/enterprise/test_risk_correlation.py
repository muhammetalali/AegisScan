from __future__ import annotations

from asgiref.sync import async_to_sync
from django.core.exceptions import ValidationError
from django.utils import timezone
import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.intelligence.models import IntelligenceEnrichment
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import (
    AttackPath,
    FindingIntelligence,
    Organization,
    RiskCorrelationSnapshot,
)
from fastapi_app.routers.risk_correlation import CorrelationRequest, _correlate_project
from fastapi_app.services.risk_correlation import correlate_finding


@pytest.fixture
def correlation_context(db):
    user = User.objects.create_user(
        email='risk-correlation@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='Risk correlation reality',
        slug='risk-correlation-reality',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Affected web service',
        slug='affected-web-service',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'http://127.0.0.1'},
    )
    scan = Scan.objects.create(
        project=project,
        name='Nuclei evidence',
        scan_type=Scan.Type.URL,
        asset=asset,
        initiated_by=user,
    )
    finding = Vulnerability.objects.create(
        project=project,
        scan=scan,
        asset=asset,
        title='CVE-backed finding',
        severity=Vulnerability.Severity.HIGH,
        risk_score=80.0,
        cve_ids=['CVE-2012-1823'],
        source_engine='nuclei',
    )
    Evidence.objects.create(
        scan=scan,
        asset=asset,
        finding=finding,
        source='nuclei',
        evidence_type='scanner_output',
        raw_output='real scanner evidence',
        collected_by=user,
    )
    snapshot = IntelligenceEnrichment.objects.create(
        cve_id='CVE-2012-1823',
        sources={
            'nvd': {'id': 'CVE-2012-1823'},
            'osv': {},
            'cisa_kev': {'known_exploited': True, 'entry': {'cveID': 'CVE-2012-1823'}},
            'epss': {'data': [{'cve': 'CVE-2012-1823', 'epss': '0.99998'}]},
        },
        source_urls={},
        provider_failures=[],
        confidence=85.0,
        conflicts=[],
        recommendation='Prioritize remediation.',
        explanation='Evidence-backed provider fusion.',
        observed_at=timezone.now(),
        observed_by=user,
    )
    intel = FindingIntelligence.objects.create(
        vulnerability=finding,
        source_snapshot=snapshot,
        primary_cve='CVE-2012-1823',
        nvd=snapshot.sources['nvd'],
        osv=snapshot.sources['osv'],
        cisa_kev=snapshot.sources['cisa_kev'],
        epss=snapshot.sources['epss'],
        confidence=snapshot.confidence,
        conflict=False,
        explanation=snapshot.explanation,
        recommendation=snapshot.recommendation,
    )
    organization = Organization.objects.create(
        name='Risk tenant',
        slug='risk-tenant',
        owner=user,
    )
    path = AttackPath.objects.create(
        organization=organization,
        project=project,
        source_node={'asset_id': str(asset.id), 'name': asset.name},
        target_node={'asset_id': str(asset.id), 'name': asset.name},
        steps=[str(asset.id)],
        risk_score=100.0,
        evidence={'source': 'asset_relationships_and_open_vulnerabilities', 'contract_version': '1.0'},
    )
    return user, project, asset, scan, finding, intel, snapshot, path


@pytest.mark.django_db
def test_correlation_is_deterministic_persisted_and_evidence_backed(correlation_context):
    user, project, _, _, finding, intel, snapshot, path = correlation_context

    row, created = correlate_finding(finding, actor_id=str(user.id))
    assert created is True
    assert row.project_id == project.id
    assert row.finding_intelligence_id == intel.pk
    assert row.source_snapshot_id == snapshot.id
    assert row.attack_path_id == path.id
    assert row.source_snapshot_sha256 == snapshot.snapshot_sha256
    assert row.analysis_version == '1.1'
    assert row.score == 100.0
    assert row.priority == RiskCorrelationSnapshot.Priority.P0_CRITICAL
    assert row.evidence_count == 1
    assert row.components['cisa_kev'] is True
    assert row.components['epss_probability'] == pytest.approx(0.99998)
    assert row.components['attack_path_risk'] == 100.0
    assert len(row.correlation_sha256) == 64

    replay, replay_created = correlate_finding(finding, actor_id=str(user.id))
    assert replay_created is False
    assert replay.id == row.id
    assert RiskCorrelationSnapshot.objects.filter(vulnerability=finding).count() == 1

    Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source='validation',
        evidence_type='validation_output',
        raw_output='independent validation evidence',
        metadata={'finding_present': True},
        collected_by=user,
    )
    changed, changed_created = correlate_finding(finding, actor_id=str(user.id))
    assert changed_created is True
    assert changed.id != row.id
    assert changed.evidence_count == 2
    assert changed.components['supporting_evidence_count'] == 2
    assert changed.components['contradicting_evidence_count'] == 0
    assert changed.components['evidence_strength'] == 60.0
    assert changed.correlation_sha256 != row.correlation_sha256
    assert RiskCorrelationSnapshot.objects.filter(vulnerability=finding).count() == 2


@pytest.mark.django_db
def test_negative_validation_changes_lineage_without_increasing_risk(correlation_context):
    user, _, _, _, finding, _, _, _ = correlation_context

    baseline, baseline_created = correlate_finding(finding, actor_id=str(user.id))
    assert baseline_created is True
    assert baseline.evidence_count == 1
    assert baseline.components['supporting_evidence_count'] == 1
    assert baseline.components['contradicting_evidence_count'] == 0
    assert baseline.components['evidence_strength'] == 55.0

    Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source='nuclei',
        evidence_type='validation_output',
        raw_output='exact template did not reproduce the finding',
        metadata={'finding_present': False},
        collected_by=user,
    )

    changed, changed_created = correlate_finding(finding, actor_id=str(user.id))

    assert changed_created is True
    assert changed.id != baseline.id
    assert changed.evidence_count == 2
    assert changed.components['supporting_evidence_count'] == 1
    assert changed.components['contradicting_evidence_count'] == 1
    assert changed.components['neutral_evidence_count'] == 0
    assert changed.components['evidence_strength'] == 55.0
    assert changed.score == baseline.score
    assert changed.priority == baseline.priority
    assert changed.correlation_sha256 != baseline.correlation_sha256


@pytest.mark.django_db
def test_correlation_snapshot_is_immutable(correlation_context):
    user, _, _, _, finding, _, _, _ = correlation_context
    row, _ = correlate_finding(finding, actor_id=str(user.id))
    row.score = 1.0
    with pytest.raises(ValidationError, match='immutable'):
        row.save()
    with pytest.raises(ValidationError, match='immutable'):
        row.delete()


@pytest.mark.django_db
def test_project_correlation_enforces_tenant_access_and_reuses_snapshot(correlation_context):
    user, project, _, scan, _, _, _, _ = correlation_context

    response = async_to_sync(_correlate_project)(
        str(project.id),
        str(user.id),
        CorrelationRequest(scan_id=str(scan.id)),
    )
    assert response.project_id == str(project.id)
    assert response.analyzed == 1
    assert response.created == 1
    assert response.reused == 0
    assert response.failures == []
    assert len(response.items) == 1
    assert response.items[0].priority == 'P0-CRITICAL'

    replay = async_to_sync(_correlate_project)(
        str(project.id),
        str(user.id),
        CorrelationRequest(scan_id=str(scan.id)),
    )
    assert replay.created == 0
    assert replay.reused == 1

    outsider = User.objects.create_user(
        email='risk-outsider@example.invalid',
        password='Strong-Test-Password-123!',
    )
    with pytest.raises(Exception) as exc:
        async_to_sync(_correlate_project)(
            str(project.id),
            str(outsider.id),
            CorrelationRequest(scan_id=str(scan.id)),
        )
    assert getattr(exc.value, 'status_code', None) == 404


@pytest.mark.django_db
def test_risk_correlation_routes_are_wired(correlation_context):
    from fastapi_app.main import app

    paths = set(app.openapi().get('paths', {}))
    assert '/api/v1/risk-correlation/projects/{project_id}/correlate' in paths
    assert '/api/v1/risk-correlation/projects/{project_id}' in paths
    assert '/api/v1/risk-correlation/findings/{finding_id}/latest' in paths
