from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from asgiref.sync import sync_to_async
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.evidence.models import FindingDisposition
from django_project.intelligence.models import IntelligenceEnrichment
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from enterprise.models import (
    FindingIntelligence,
    Organization,
    OrganizationMembership,
    RiskCorrelationSnapshot,
    TenantProject,
)
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.services.finding_disposition import (
    FindingDispositionError,
    govern_finding_disposition,
)


pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def disposition_fixture(transactional_db):
    user = User.objects.create_user(
        email='finding-disposition@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Finding',
        last_name='Disposition',
    )
    project = Project.objects.create(
        name='Finding Disposition Reality',
        slug='finding-disposition-reality',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name='Disposition Target',
        slug='disposition-target',
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={'host': 'aegis-disposition-target', 'authorized': True},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='aegis-disposition-target',
        reason='Governed finding disposition reality grant',
    )
    scan = Scan.objects.create(
        project=project,
        name='Disposition Source Scan',
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=['nmap'],
        config={'target': 'aegis-disposition-target'},
        initiated_by=user,
        authorization_decision=authorization,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Governed disposition finding',
        description='Source finding for governed disposition reality.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.CONFIRMED,
        source_engine='nmap',
        raw_data={'port': 443, 'state': 'open'},
    )
    organization = Organization.objects.create(
        name='Disposition Tenant',
        slug='disposition-tenant',
        owner=user,
        is_active=True,
    )
    membership = OrganizationMembership.objects.create(
        organization=organization,
        user=user,
        role=OrganizationMembership.Role.MANAGER,
        is_active=True,
    )
    TenantProject.objects.create(organization=organization, project=project)

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(user.id),
        'is_staff': True,
    }
    client = TestClient(app)
    with client:
        try:
            yield client, user, project, asset, authorization, scan, finding, organization, membership
        finally:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
            app.dependency_overrides.clear()


def _risk_snapshot(*, user: User, project: Project, finding: Vulnerability, marker: str) -> RiskCorrelationSnapshot:
    enrichment = IntelligenceEnrichment.objects.create(
        cve_id=f'CVE-2099-{marker[-4:].upper()}',
        sources={'test': {'marker': marker}},
        source_urls={'test': 'https://example.invalid/intelligence'},
        confidence=0.95,
        recommendation='Governed risk decision evidence.',
        explanation='Reality-test immutable intelligence snapshot.',
        observed_at=datetime.now(timezone.utc),
        observed_by=user,
    )
    intelligence, _ = FindingIntelligence.objects.get_or_create(
        vulnerability=finding,
        defaults={
            'source_snapshot': enrichment,
            'primary_cve': enrichment.cve_id,
            'confidence': 0.95,
            'explanation': 'Reality-test finding intelligence.',
            'recommendation': 'Review governed disposition.',
        },
    )
    digest = hashlib.sha256(f'{finding.id}:{marker}'.encode()).hexdigest()
    return RiskCorrelationSnapshot.objects.create(
        project=project,
        vulnerability=finding,
        finding_intelligence=intelligence,
        source_snapshot=enrichment,
        score=82.0,
        priority=RiskCorrelationSnapshot.Priority.P1_HIGH,
        components={'marker': marker, 'exploitability': 0.8, 'impact': 0.9},
        evidence_count=1,
        source_snapshot_sha256=enrichment.snapshot_sha256,
        correlation_sha256=digest,
        created_by=user,
    )


def _other_finding(*, user: User, project: Project, asset: Asset, scan: Scan, title: str = 'Other finding') -> Vulnerability:
    return Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title=title,
        description='Additional finding for disposition reality.',
        severity=Vulnerability.Severity.MEDIUM,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
    )


def _risk_body(risk: RiskCorrelationSnapshot, disposition: str = 'accepted_risk', rationale: str = 'Documented tenant risk decision.') -> dict:
    return {
        'disposition': disposition,
        'rationale': rationale,
        'risk_correlation_id': str(risk.id),
        'review_at': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }


def test_accepted_risk_creates_immutable_lineage_history_and_audit(disposition_fixture):
    client, user, project, _asset, _authorization, _scan, finding, organization, membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='accepted-risk')

    response = client.post(f'/api/v1/vulnerabilities/{finding.id}/dispositions', json=_risk_body(risk))

    assert response.status_code == 201
    payload = response.json()
    assert payload['disposition'] == 'accepted_risk'
    assert payload['organization_id'] == str(organization.id)
    assert payload['risk_correlation_id'] == str(risk.id)
    assert payload['approving_role'] == membership.role
    assert payload['policy_version'] == 'finding-disposition.v1'
    assert len(payload['risk_correlation_sha256']) == 64
    assert payload['replayed'] is False

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.ACCEPTED_RISK
    record = FindingDisposition.objects.get(pk=payload['id'])
    assert record.risk_correlation_id == risk.id
    assert record.review_at > datetime.now(timezone.utc)
    history = VulnerabilityStatusHistory.objects.get(vulnerability=finding)
    assert history.old_status == Vulnerability.Status.OPEN
    assert history.new_status == Vulnerability.Status.ACCEPTED_RISK
    audit = AuditLog.objects.filter(
        action=AuditLog.Action.VULN_STATUS_CHANGE,
        resource_id=str(finding.id),
        metadata__operation='finding_disposition',
    ).get()
    assert audit.metadata['disposition_id'] == payload['id']
    assert audit.metadata['risk_correlation_id'] == str(risk.id)
    assert audit.metadata['organization_id'] == str(organization.id)


def test_wont_fix_can_follow_accepted_risk_with_fresh_latest_risk(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    first_risk = _risk_snapshot(user=user, project=project, finding=finding, marker='risk-one')
    first = govern_finding_disposition(
        finding_id=finding.id,
        disposition='accepted_risk',
        rationale='Initial accepted risk decision.',
        actor_id=user.id,
        risk_correlation_id=first_risk.id,
        review_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    assert first.status_changed is True
    second_risk = _risk_snapshot(user=user, project=project, finding=finding, marker='risk-two')

    second = govern_finding_disposition(
        finding_id=finding.id,
        disposition='wont_fix',
        rationale='Subsequent governed wont-fix decision.',
        actor_id=user.id,
        risk_correlation_id=second_risk.id,
        review_at=datetime.now(timezone.utc) + timedelta(days=45),
    )

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.WONT_FIX
    assert second.disposition.risk_correlation_id == second_risk.id
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding).count() == 2


@pytest.mark.parametrize('role', [
    OrganizationMembership.Role.ANALYST,
    OrganizationMembership.Role.AUDITOR,
    OrganizationMembership.Role.VIEWER,
])
def test_non_governance_roles_cannot_accept_risk(disposition_fixture, role):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, membership = disposition_fixture
    membership.role = role
    membership.save(update_fields=['role'])
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker=f'role-{role}')

    with pytest.raises(FindingDispositionError, match='not authorized'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='accepted_risk',
            rationale='Unauthorized risk decision must fail.',
            actor_id=user.id,
            risk_correlation_id=risk.id,
            review_at=datetime.now(timezone.utc) + timedelta(days=30),
        )

    assert FindingDisposition.objects.count() == 0


def test_analyst_can_mark_duplicate_with_same_project_canonical_target(disposition_fixture):
    _client, user, project, asset, _authorization, scan, finding, _organization, membership = disposition_fixture
    membership.role = OrganizationMembership.Role.ANALYST
    membership.save(update_fields=['role'])
    root = _other_finding(user=user, project=project, asset=asset, scan=scan, title='Canonical root')
    intermediate = _other_finding(user=user, project=project, asset=asset, scan=scan, title='Intermediate duplicate')
    intermediate.status = Vulnerability.Status.DUPLICATE
    intermediate.duplicate_of = root
    intermediate.save(update_fields=['status', 'duplicate_of', 'updated_at'])

    result = govern_finding_disposition(
        finding_id=finding.id,
        disposition='duplicate',
        rationale='Same issue as canonical active root.',
        actor_id=user.id,
        duplicate_of_id=intermediate.id,
    )

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.DUPLICATE
    assert finding.duplicate_of_id == root.id
    assert result.disposition.duplicate_of_id == root.id
    assert result.disposition.approving_role == OrganizationMembership.Role.ANALYST


def test_inactive_membership_is_fail_closed(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, membership = disposition_fixture
    membership.is_active = False
    membership.save(update_fields=['is_active'])
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='inactive-member')

    with pytest.raises(FindingDispositionError, match='no active membership'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='accepted_risk',
            rationale='Inactive membership must never authorize risk.',
            actor_id=user.id,
            risk_correlation_id=risk.id,
            review_at=datetime.now(timezone.utc) + timedelta(days=30),
        )


def test_stale_risk_snapshot_is_rejected(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    stale = _risk_snapshot(user=user, project=project, finding=finding, marker='stale')
    latest = _risk_snapshot(user=user, project=project, finding=finding, marker='latest')
    assert latest.id != stale.id

    with pytest.raises(FindingDispositionError, match='latest immutable risk'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='accepted_risk',
            rationale='Stale risk must not authorize disposition.',
            actor_id=user.id,
            risk_correlation_id=stale.id,
            review_at=datetime.now(timezone.utc) + timedelta(days=30),
        )


def test_risk_snapshot_from_another_finding_is_rejected(disposition_fixture):
    _client, user, project, asset, _authorization, scan, finding, _organization, _membership = disposition_fixture
    other = _other_finding(user=user, project=project, asset=asset, scan=scan)
    risk = _risk_snapshot(user=user, project=project, finding=other, marker='wrong-finding')

    with pytest.raises(FindingDispositionError, match='does not belong'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='wont_fix',
            rationale='Cross-finding risk lineage must fail.',
            actor_id=user.id,
            risk_correlation_id=risk.id,
            review_at=datetime.now(timezone.utc) + timedelta(days=30),
        )


@pytest.mark.parametrize('review_delta, message', [
    (timedelta(days=-1), 'future'),
    (timedelta(days=366), '365 days'),
])
def test_review_window_is_bounded(disposition_fixture, review_delta, message):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker=f'review-{review_delta.days}')

    with pytest.raises(FindingDispositionError, match=message):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='accepted_risk',
            rationale='Review policy boundary proof.',
            actor_id=user.id,
            risk_correlation_id=risk.id,
            review_at=datetime.now(timezone.utc) + review_delta,
        )


def test_missing_review_at_is_rejected(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='missing-review')
    with pytest.raises(FindingDispositionError, match='require review_at'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='accepted_risk',
            rationale='Missing review date must fail.',
            actor_id=user.id,
            risk_correlation_id=risk.id,
        )


def test_duplicate_self_and_cycle_are_rejected(disposition_fixture):
    _client, user, project, asset, _authorization, scan, finding, _organization, _membership = disposition_fixture
    with pytest.raises(FindingDispositionError, match='duplicate of itself'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='duplicate',
            rationale='Self duplicate must fail.',
            actor_id=user.id,
            duplicate_of_id=finding.id,
        )

    target = _other_finding(user=user, project=project, asset=asset, scan=scan, title='Cycle target')
    target.status = Vulnerability.Status.DUPLICATE
    target.duplicate_of = finding
    target.save(update_fields=['status', 'duplicate_of', 'updated_at'])
    with pytest.raises(FindingDispositionError, match='cycle'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='duplicate',
            rationale='Cycle must fail.',
            actor_id=user.id,
            duplicate_of_id=target.id,
        )


def test_duplicate_cross_project_is_rejected(disposition_fixture):
    _client, user, _project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    other_project = Project.objects.create(name='Other project', slug='other-disposition-project', owner=user)
    other_asset = Asset.objects.create(
        project=other_project,
        name='Other target',
        slug='other-disposition-target',
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.MEDIUM,
        configuration={'host': 'other-target'},
        owner=user,
    )
    other_scan = Scan.objects.create(
        project=other_project,
        name='Other scan',
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=other_asset,
        engines=['nmap'],
        config={'target': 'other-target'},
        initiated_by=user,
    )
    other = _other_finding(user=user, project=other_project, asset=other_asset, scan=other_scan)

    with pytest.raises(FindingDispositionError, match='same project'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='duplicate',
            rationale='Cross-project duplicate must fail.',
            actor_id=user.id,
            duplicate_of_id=other.id,
        )


def test_duplicate_terminal_false_positive_or_fixed_is_rejected(disposition_fixture):
    _client, user, project, asset, _authorization, scan, finding, _organization, _membership = disposition_fixture
    target = _other_finding(user=user, project=project, asset=asset, scan=scan, title='Closed duplicate target')
    target.status = Vulnerability.Status.FALSE_POSITIVE
    target.save(update_fields=['status', 'updated_at'])

    with pytest.raises(FindingDispositionError, match='active governed finding'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='duplicate',
            rationale='Terminal duplicate target must fail.',
            actor_id=user.id,
            duplicate_of_id=target.id,
        )


def test_exact_replay_has_one_record_history_and_audit(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='replay')
    review_at = datetime.now(timezone.utc) + timedelta(days=30)

    first = govern_finding_disposition(
        finding_id=finding.id,
        disposition='accepted_risk',
        rationale='  Same   governed replay. ',
        actor_id=user.id,
        risk_correlation_id=risk.id,
        review_at=review_at,
    )
    second = govern_finding_disposition(
        finding_id=finding.id,
        disposition='accepted_risk',
        rationale='Same governed replay.',
        actor_id=user.id,
        risk_correlation_id=risk.id,
        review_at=review_at,
    )

    assert first.replayed is False
    assert second.replayed is True
    assert first.disposition.id == second.disposition.id
    assert FindingDisposition.objects.filter(finding=finding).count() == 1
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding).count() == 1
    assert AuditLog.objects.filter(resource_id=str(finding.id), metadata__operation='finding_disposition').count() == 1


def test_changed_semantics_after_same_disposition_are_rejected(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='changed-semantics')
    review_at = datetime.now(timezone.utc) + timedelta(days=30)
    govern_finding_disposition(
        finding_id=finding.id,
        disposition='accepted_risk',
        rationale='First immutable rationale.',
        actor_id=user.id,
        risk_correlation_id=risk.id,
        review_at=review_at,
    )

    with pytest.raises(FindingDispositionError, match='different immutable semantics'):
        govern_finding_disposition(
            finding_id=finding.id,
            disposition='accepted_risk',
            rationale='Changed immutable rationale.',
            actor_id=user.id,
            risk_correlation_id=risk.id,
            review_at=review_at,
        )


@pytest.mark.parametrize('status', ['accepted_risk', 'wont_fix', 'duplicate'])
def test_direct_patch_cannot_bypass_disposition_governance(disposition_fixture, status):
    client, _user, _project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    response = client.patch(f'/api/v1/vulnerabilities/{finding.id}', json={'status': status})
    assert response.status_code == 409
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN


@pytest.mark.parametrize('status', ['accepted_risk', 'wont_fix', 'duplicate'])
def test_bulk_update_cannot_bypass_disposition_governance(disposition_fixture, status):
    client, _user, _project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    response = client.post(
        '/api/v1/vulnerabilities/bulk-update',
        json={'vuln_ids': [str(finding.id)], 'update': {'status': status}},
    )
    assert response.status_code == 409
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN


def test_contract_forbids_unknown_fields(disposition_fixture):
    client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='strict-contract')
    body = _risk_body(risk)
    body['approval_token'] = 'must-not-be-accepted'
    response = client.post(f'/api/v1/vulnerabilities/{finding.id}/dispositions', json=body)
    assert response.status_code == 422
    assert FindingDisposition.objects.count() == 0


def test_endpoint_is_project_scoped(disposition_fixture):
    client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='tenant-scope')
    outsider = User.objects.create_user(email='disposition-outsider@example.invalid', password='Strong-Test-Password-123!')
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {'user_id': str(outsider.id), 'is_staff': True}
    response = client.post(f'/api/v1/vulnerabilities/{finding.id}/dispositions', json=_risk_body(risk))
    assert response.status_code == 404
    assert FindingDisposition.objects.count() == 0


def test_disposition_records_are_append_only(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='append-only')
    record = govern_finding_disposition(
        finding_id=finding.id,
        disposition='accepted_risk',
        rationale='Append-only proof.',
        actor_id=user.id,
        risk_correlation_id=risk.id,
        review_at=datetime.now(timezone.utc) + timedelta(days=30),
    ).disposition
    record.rationale = 'tampered'
    with pytest.raises(ValidationError):
        record.save()
    with pytest.raises(ValidationError):
        record.delete()
    with pytest.raises(ValidationError):
        FindingDisposition.objects.filter(pk=record.pk).update(rationale='tampered')
    with pytest.raises(ValidationError):
        FindingDisposition.objects.filter(pk=record.pk).delete()


def test_database_rejects_invalid_lineage_shape(disposition_fixture):
    _client, user, _project, _asset, _authorization, _scan, finding, organization, membership = disposition_fixture
    with pytest.raises(IntegrityError):
        FindingDisposition.objects.create(
            finding=finding,
            disposition='accepted_risk',
            organization=organization,
            risk_correlation=None,
            duplicate_of=None,
            created_by=user,
            approving_role=membership.role,
            risk_correlation_sha256='',
            request_fingerprint='f' * 64,
            rationale='Invalid DB shape must fail.',
            review_at=None,
        )


def test_postgresql_concurrent_exact_request_creates_one_immutable_decision(disposition_fixture):
    _client, user, project, _asset, _authorization, _scan, finding, _organization, _membership = disposition_fixture
    assert connection.vendor == 'postgresql'
    risk = _risk_snapshot(user=user, project=project, finding=finding, marker='concurrency')
    review_at = datetime.now(timezone.utc) + timedelta(days=30)

    def worker():
        connections.close_all()
        try:
            return govern_finding_disposition(
                finding_id=finding.id,
                disposition='accepted_risk',
                rationale='Concurrent exact governed decision.',
                actor_id=user.id,
                risk_correlation_id=risk.id,
                review_at=review_at,
            )
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: worker(), range(2)))

    assert sorted(result.replayed for result in results) == [False, True]
    assert FindingDisposition.objects.filter(finding=finding).count() == 1
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding).count() == 1
    assert AuditLog.objects.filter(resource_id=str(finding.id), metadata__operation='finding_disposition').count() == 1
