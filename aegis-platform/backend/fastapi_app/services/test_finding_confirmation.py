from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from asgiref.sync import sync_to_async
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, connections
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.evidence.models import Evidence, FindingConfirmation, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.services import finding_confirmation as confirmation_service
from fastapi_app.services.finding_confirmation import FindingConfirmationError, confirm_finding


pytestmark = pytest.mark.django_db(transaction=True)


async def _close_django_connections_for_testclient() -> None:
    await sync_to_async(connections.close_all, thread_sensitive=True)()


@pytest.fixture
def confirmation_fixture(transactional_db, monkeypatch):
    user = User.objects.create_user(
        email='finding-confirmation@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Finding',
        last_name='Confirmation',
    )
    project = Project.objects.create(
        name='Finding Confirmation Reality',
        slug='finding-confirmation-reality',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        name='Confirmation Target',
        slug='confirmation-target',
        type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION,
        criticality=Asset.Criticality.HIGH,
        configuration={'host': 'aegis-confirmation-target', 'authorized': True},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='aegis-confirmation-target',
        reason='Governed finding confirmation reality grant',
    )
    scan = Scan.objects.create(
        project=project,
        name='Confirmation Source Scan',
        scan_type=Scan.Type.NETWORK,
        depth=Scan.Depth.QUICK,
        asset=asset,
        engines=['nmap'],
        config={'target': 'aegis-confirmation-target'},
        initiated_by=user,
        authorization_decision=authorization,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Exposed TCP port 443',
        description='Source finding for governed confirmation reality.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
        raw_data={'port': 443, 'state': 'open', 'protocol': 'tcp', 'service': 'https'},
    )

    monkeypatch.setattr(
        confirmation_service,
        'require_bound_validation_authorization',
        lambda validation: (asset, authorization.target_snapshot, authorization),
    )

    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(user.id),
        'is_staff': True,
    }
    client = TestClient(app)
    with client:
        try:
            yield client, user, project, asset, authorization, scan, finding
        finally:
            if client.portal is not None:
                client.portal.call(_close_django_connections_for_testclient)
            app.dependency_overrides.clear()


def _completed_validation(
    *,
    user: User,
    finding: Vulnerability,
    authorization: AssetAuthorization,
    finding_present: bool,
    evidence_authorization_id: str | None = None,
) -> tuple[ValidationRun, Evidence]:
    validation = ValidationRun.objects.create(
        user=user,
        finding=finding,
        authorization_decision=authorization,
        target_type='ip',
        target_value='aegis-confirmation-target',
        scope='aegis-confirmation-target',
        profile='quick',
        engines=['nmap'],
        authorized=True,
        status=ValidationRun.Status.COMPLETED,
        progress=100,
        current_phase='completed',
        result={
            'tool': 'nmap',
            'target': 'aegis-confirmation-target',
            'exit_code': 0,
            'finding_present': finding_present,
            'port': 443,
        },
        completed_at=datetime.now(timezone.utc),
    )
    evidence = Evidence.objects.create(
        scan=finding.scan,
        asset=finding.asset,
        finding=finding,
        source='nmap',
        evidence_type='validation_output',
        raw_output='<nmaprun><port portid="443" /></nmaprun>',
        metadata={
            'format': 'xml',
            'validation_run_id': str(validation.id),
            'validation_id': str(validation.id),
            'finding_present': finding_present,
            'authorization_decision_id': evidence_authorization_id or str(authorization.id),
        },
        collected_by=user,
    )
    validation.result = {**validation.result, 'evidence_id': str(evidence.id)}
    validation.save(update_fields=['result'])
    return validation, evidence


def _confirmation_body(validation: ValidationRun, verdict: str, rationale: str = 'Independent authorized re-validation evidence.') -> dict:
    return {
        'validation_id': str(validation.id),
        'verdict': verdict,
        'rationale': rationale,
    }


def test_positive_validation_creates_confirmed_verdict_and_lineage(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, evidence = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed'),
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload['verdict'] == 'confirmed'
    assert payload['finding_present'] is True
    assert payload['validation_id'] == str(validation.id)
    assert payload['evidence_id'] == str(evidence.id)
    assert payload['authorization_decision_id'] == str(authorization.id)
    assert payload['evidence_sha256'] == evidence.sha256
    assert len(payload['result_sha256']) == 64
    assert payload['policy_version'] == 'finding-confirmation.v1'
    assert payload['replayed'] is False

    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.CONFIRMED
    assert finding.confidence == Vulnerability.Confidence.CONFIRMED
    assert finding.validation_status == 'confirmed'
    assert finding.validated_by_id == user.id
    assert FindingConfirmation.objects.filter(finding=finding, validation_run=validation).count() == 1
    history = VulnerabilityStatusHistory.objects.get(vulnerability=finding)
    assert history.old_status == Vulnerability.Status.OPEN
    assert history.new_status == Vulnerability.Status.CONFIRMED
    audit = AuditLog.objects.filter(
        action=AuditLog.Action.VULN_STATUS_CHANGE,
        resource_id=str(finding.id),
        metadata__operation='finding_confirmation',
    ).get()
    assert audit.metadata['confirmation_id'] == payload['id']
    assert audit.metadata['evidence_sha256'] == evidence.sha256


def test_negative_validation_can_govern_open_finding_as_false_positive(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=False,
    )

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'false_positive', 'Exact re-validation did not reproduce the source finding.'),
    )

    assert response.status_code == 201
    assert response.json()['finding_present'] is False
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.FALSE_POSITIVE
    assert finding.validation_status == 'false_positive'


def test_verdict_must_match_validation_and_evidence_polarity(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'false_positive'),
    )

    assert response.status_code == 409
    assert 'conflicts with validation' in response.json()['detail']
    assert FindingConfirmation.objects.count() == 0


def test_authorization_lineage_mismatch_is_rejected(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
        evidence_authorization_id='00000000-0000-0000-0000-000000000001',
    )

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed'),
    )

    assert response.status_code == 409
    assert 'authorization lineage' in response.json()['detail']
    assert FindingConfirmation.objects.count() == 0


def test_validation_from_another_finding_is_rejected(confirmation_fixture):
    client, user, project, asset, authorization, scan, finding = confirmation_fixture
    other = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Other finding',
        description='Other finding',
        severity=Vulnerability.Severity.LOW,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.HIGH,
        source_engine='nmap',
    )
    validation, _ = _completed_validation(
        user=user,
        finding=other,
        authorization=authorization,
        finding_present=True,
    )

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed'),
    )

    assert response.status_code == 409
    assert 'not found for this finding' in response.json()['detail']


def test_exact_replay_returns_same_record_without_duplicate_history_or_audit(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    body = _confirmation_body(validation, 'confirmed', '  Same   normalized rationale.  ')

    first = client.post(f'/api/v1/vulnerabilities/{finding.id}/confirmations', json=body)
    second = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed', 'Same normalized rationale.'),
    )

    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()['id'] == second.json()['id']
    assert second.json()['replayed'] is True
    assert FindingConfirmation.objects.filter(finding=finding).count() == 1
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding).count() == 1
    assert AuditLog.objects.filter(
        action=AuditLog.Action.VULN_STATUS_CHANGE,
        resource_id=str(finding.id),
        metadata__operation='finding_confirmation',
    ).count() == 1


def test_validation_cannot_be_reused_with_different_confirmation_semantics(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    first = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed', 'First governed rationale.'),
    )
    second = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed', 'Different governed rationale.'),
    )

    assert first.status_code == 201
    assert second.status_code == 409
    assert 'different semantics' in second.json()['detail']
    assert FindingConfirmation.objects.filter(finding=finding).count() == 1


@pytest.mark.parametrize('status', ['confirmed', 'false_positive', 'fixed'])
def test_direct_patch_cannot_bypass_governed_finding_statuses(confirmation_fixture, status):
    client, _user, _project, _asset, _authorization, _scan, finding = confirmation_fixture

    response = client.patch(f'/api/v1/vulnerabilities/{finding.id}', json={'status': status})

    assert response.status_code == 409
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN


@pytest.mark.parametrize('status', ['confirmed', 'false_positive', 'fixed'])
def test_bulk_update_cannot_bypass_governed_finding_statuses(confirmation_fixture, status):
    client, _user, _project, _asset, _authorization, _scan, finding = confirmation_fixture

    response = client.post(
        '/api/v1/vulnerabilities/bulk-update',
        json={'vuln_ids': [str(finding.id)], 'update': {'status': status}},
    )

    assert response.status_code == 409
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.OPEN


def test_confirmation_contract_forbids_unknown_fields(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    body = _confirmation_body(validation, 'confirmed')
    body['raw_output'] = 'must never be accepted by confirmation contract'

    response = client.post(f'/api/v1/vulnerabilities/{finding.id}/confirmations', json=body)

    assert response.status_code == 422
    assert FindingConfirmation.objects.count() == 0


def test_confirmation_endpoint_is_tenant_scoped(confirmation_fixture):
    client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    outsider = User.objects.create_user(
        email='finding-confirmation-outsider@example.invalid',
        password='Strong-Test-Password-123!',
    )
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {
        'user_id': str(outsider.id),
        'is_staff': True,
    }

    response = client.post(
        f'/api/v1/vulnerabilities/{finding.id}/confirmations',
        json=_confirmation_body(validation, 'confirmed'),
    )

    assert response.status_code == 404
    assert FindingConfirmation.objects.count() == 0


def test_confirmation_records_are_append_only(confirmation_fixture):
    _client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )
    result = confirm_finding(
        finding_id=finding.id,
        validation_id=validation.id,
        verdict='confirmed',
        rationale='Append-only proof.',
        actor_id=user.id,
    )
    record = result.confirmation

    record.rationale = 'tampered'
    with pytest.raises(ValidationError):
        record.save()
    with pytest.raises(ValidationError):
        record.delete()
    with pytest.raises(ValidationError):
        FindingConfirmation.objects.filter(pk=record.pk).update(rationale='tampered')
    with pytest.raises(ValidationError):
        FindingConfirmation.objects.filter(pk=record.pk).delete()


def test_database_rejects_verdict_presence_mismatch(confirmation_fixture):
    _client, user, _project, _asset, authorization, _scan, finding = confirmation_fixture
    validation, evidence = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )

    with pytest.raises(IntegrityError):
        FindingConfirmation.objects.create(
            finding=finding,
            validation_run=validation,
            evidence=evidence,
            authorization_decision=authorization,
            created_by=user,
            verdict='false_positive',
            finding_present=True,
            policy_version='finding-confirmation.v1',
            evidence_sha256=evidence.sha256,
            result_sha256='0' * 64,
            request_fingerprint='1' * 64,
            rationale='Invalid polarity should fail at the database.',
        )


def test_concurrent_exact_confirmation_serializes_to_one_record(confirmation_fixture):
    if connection.vendor != 'postgresql':
        pytest.skip('Row-lock concurrency proof requires PostgreSQL.')
    _client, user, _project, asset, authorization, _scan, finding = confirmation_fixture
    validation, _ = _completed_validation(
        user=user,
        finding=finding,
        authorization=authorization,
        finding_present=True,
    )

    original_preflight = confirmation_service.require_bound_validation_authorization

    def call_confirmation():
        connections.close_all()
        try:
            confirmation_service.require_bound_validation_authorization = lambda current: (
                Asset.objects.get(pk=asset.pk),
                authorization.target_snapshot,
                AssetAuthorization.objects.get(pk=authorization.pk),
            )
            result = confirm_finding(
                finding_id=finding.id,
                validation_id=validation.id,
                verdict='confirmed',
                rationale='Concurrent exact confirmation.',
                actor_id=user.id,
            )
            return str(result.confirmation.id), result.replayed
        finally:
            connections.close_all()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: call_confirmation(), range(2)))
    finally:
        confirmation_service.require_bound_validation_authorization = original_preflight

    assert len({item[0] for item in outcomes}) == 1
    assert sorted(item[1] for item in outcomes) == [False, True]
    assert FindingConfirmation.objects.filter(finding=finding).count() == 1
    assert VulnerabilityStatusHistory.objects.filter(vulnerability=finding).count() == 1
