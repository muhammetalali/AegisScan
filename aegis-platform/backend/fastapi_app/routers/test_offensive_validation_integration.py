from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from asgiref.sync import async_to_sync
from fastapi import HTTPException

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.routers import validations
from fastapi_app.services.offensive_validation import ENGINE


class _ImmediateTaskResult:
    id = 'local-offensive-validation-task'


@pytest.fixture
def browser_transport_finding(db, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    user = User.objects.create_user(email='offensive-api-owner@example.invalid', password='Strong-Test-Password-123!')
    other = User.objects.create_user(email='offensive-api-other@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Offensive API', slug='offensive-api', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Authorized web app',
        slug='authorized-web-app',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'http://127.0.0.1/login'},
    )
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='http://127.0.0.1/login',
        reason='authorized lab endpoint',
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='Browser finding source',
        scan_type=Scan.Type.URL,
        engines=['browser.dom-snapshot'],
        config={'target': 'http://127.0.0.1/login'},
        initiated_by=user,
        status=Scan.Status.COMPLETED,
    )
    raw_browser = json.dumps({
        'schema': 'aegis.browser-security.v1',
        'target_url': 'http://127.0.0.1/login',
        'observations': [{
            'kind': 'browser-dom-security-snapshot',
            'insecure_form_actions': ['http://127.0.0.1/login'],
            'mixed_content_urls': [],
        }],
    }, sort_keys=True)
    Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='browser-security',
        evidence_type='browser_dom_snapshot',
        raw_output=raw_browser,
        metadata={'schema': 'aegis.browser-security.v1'},
        collected_by=user,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Form submits data over cleartext HTTP',
        description='Browser evidence detected cleartext form transport.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.ACCEPTED_RISK,
        confidence=Vulnerability.Confidence.UNVERIFIED,
        category='browser-security',
        cwe_id='CWE-319',
        tags=['browser.insecure-form-action'],
        url='http://127.0.0.1/login',
        source_engine='aegis-browser-security',
        raw_data={
            'rule_id': 'browser.insecure-form-action',
            'affected_urls': ['http://127.0.0.1/login'],
        },
    )
    return SimpleNamespace(user=user, other=other, project=project, asset=asset, scan=scan, finding=finding)


@pytest.mark.django_db
def test_offensive_validation_api_runs_celery_task_to_evidence(browser_transport_finding, monkeypatch):
    def immediate_delay(validation_id: str):
        from fastapi_app.tasks.offensive_validation_tasks import validate_offensive_finding
        validate_offensive_finding.run(validation_id)
        return _ImmediateTaskResult()

    monkeypatch.setattr(validations.validate_offensive_finding, 'delay', immediate_delay)

    body = validations.OffensiveValidationCreate(
        finding_id=browser_transport_finding.finding.id,
        profile='standard',
        authorized=True,
    )
    response = async_to_sync(validations.create_offensive_validation)(
        body,
        user={'user_id': str(browser_transport_finding.user.id)},
    )

    run = ValidationRun.objects.get(id=response.id)
    assert response.engines == [ENGINE]
    assert response.celery_task_id == _ImmediateTaskResult.id
    assert run.status == ValidationRun.Status.COMPLETED
    assert run.progress == 100
    assert run.result['engine'] == ENGINE
    assert run.result['exploitability']['state'] == 'confirmed'
    assert run.result['runtime']['live_session_opened'] is False

    evidence = Evidence.objects.get(id=run.result['evidence_id'])
    assert evidence.finding_id == browser_transport_finding.finding.id
    assert evidence.source == ENGINE
    assert evidence.evidence_type == 'exploitability_proof'
    assert evidence.metadata['validation_run_id'] == str(run.id)
    assert evidence.metadata['authorization_decision_id'] == str(run.authorization_decision_id)

    result_response = async_to_sync(validations.get_validation_result)(
        run.id,
        user={'user_id': str(browser_transport_finding.user.id)},
    )
    assert result_response.result['evidence_id'] == str(evidence.id)
    assert result_response.result['exploitability']['state'] == 'confirmed'

    evidence_response = async_to_sync(validations.get_validation_evidence)(
        run.id,
        user={'user_id': str(browser_transport_finding.user.id)},
    )
    assert [item.id for item in evidence_response] == [str(evidence.id)]
    assert evidence_response[0].sha256 == evidence.sha256

    browser_transport_finding.finding.refresh_from_db()
    assert browser_transport_finding.finding.status == Vulnerability.Status.ACCEPTED_RISK
    assert browser_transport_finding.finding.validation_status == 'confirmed'
    assert browser_transport_finding.finding.verified_evidence_count >= 1


@pytest.mark.django_db
def test_offensive_validation_result_and_evidence_are_tenant_scoped(browser_transport_finding, monkeypatch):
    def immediate_delay(validation_id: str):
        from fastapi_app.tasks.offensive_validation_tasks import validate_offensive_finding
        validate_offensive_finding.run(validation_id)
        return _ImmediateTaskResult()

    monkeypatch.setattr(validations.validate_offensive_finding, 'delay', immediate_delay)
    response = async_to_sync(validations.create_offensive_validation)(
        validations.OffensiveValidationCreate(finding_id=browser_transport_finding.finding.id),
        user={'user_id': str(browser_transport_finding.user.id)},
    )

    with pytest.raises(HTTPException) as result_error:
        async_to_sync(validations.get_validation_result)(
            response.id,
            user={'user_id': str(browser_transport_finding.other.id)},
        )
    assert result_error.value.status_code == 404

    with pytest.raises(HTTPException) as evidence_error:
        async_to_sync(validations.get_validation_evidence)(
            response.id,
            user={'user_id': str(browser_transport_finding.other.id)},
        )
    assert evidence_error.value.status_code == 404


@pytest.mark.django_db
def test_offensive_validation_cancel_endpoint_preserves_terminal_state(browser_transport_finding):
    run = ValidationRun.objects.create(
        user=browser_transport_finding.user,
        finding=browser_transport_finding.finding,
        target_type='url',
        target_value='http://127.0.0.1/login',
        scope=str(browser_transport_finding.project.id),
        profile='standard',
        engines=[ENGINE],
        authorized=True,
        authorization_decision=AssetAuthorization.objects.filter(asset=browser_transport_finding.asset).latest('created_at'),
        status=ValidationRun.Status.QUEUED,
    )

    response = async_to_sync(validations.cancel_validation)(
        run.id,
        user={'user_id': str(browser_transport_finding.user.id)},
    )
    assert response.status == ValidationRun.Status.CANCELLED
    run.refresh_from_db()
    assert run.status == ValidationRun.Status.CANCELLED
    assert run.current_phase == 'cancelled'

    second = async_to_sync(validations.cancel_validation)(
        run.id,
        user={'user_id': str(browser_transport_finding.user.id)},
    )
    assert second.status == ValidationRun.Status.CANCELLED
