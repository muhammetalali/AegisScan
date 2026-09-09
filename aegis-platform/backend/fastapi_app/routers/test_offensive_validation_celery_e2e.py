from __future__ import annotations

import json
import time

import pytest
from asgiref.sync import async_to_sync

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.routers import validations
from fastapi_app.services.offensive_validation import ENGINE


def _fixture_finding():
    user = User.objects.create_user(email='offensive-celery-owner@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Offensive Celery', slug='offensive-celery', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Celery authorized web app',
        slug='celery-authorized-web-app',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'http://127.0.0.1/celery-login'},
    )
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='http://127.0.0.1/celery-login',
        reason='celery e2e authorized endpoint',
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='Celery browser finding source',
        scan_type=Scan.Type.URL,
        engines=['browser.dom-snapshot'],
        config={'target': 'http://127.0.0.1/celery-login'},
        initiated_by=user,
        status=Scan.Status.COMPLETED,
    )
    raw_browser = json.dumps({
        'schema': 'aegis.browser-security.v1',
        'target_url': 'http://127.0.0.1/celery-login',
        'observations': [{
            'kind': 'browser-dom-security-snapshot',
            'insecure_form_actions': ['http://127.0.0.1/celery-login'],
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
        title='Form submits data over cleartext HTTP from Celery worker',
        description='Browser evidence detected cleartext form transport.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.UNVERIFIED,
        category='browser-security',
        cwe_id='CWE-319',
        tags=['browser.insecure-form-action'],
        url='http://127.0.0.1/celery-login',
        source_engine='aegis-browser-security',
        raw_data={
            'rule_id': 'browser.insecure-form-action',
            'affected_urls': ['http://127.0.0.1/celery-login'],
        },
    )
    return user, finding


@pytest.mark.django_db(transaction=True)
def test_offensive_validation_api_to_redis_celery_worker_to_evidence():
    user, finding = _fixture_finding()
    response = async_to_sync(validations.create_offensive_validation)(
        validations.OffensiveValidationCreate(finding_id=finding.id, profile='standard', authorized=True),
        user={'user_id': str(user.id)},
    )
    assert response.engines == [ENGINE]
    assert response.celery_task_id

    deadline = time.monotonic() + 45
    run = ValidationRun.objects.get(id=response.id)
    while time.monotonic() < deadline:
        run.refresh_from_db()
        if run.status in {ValidationRun.Status.COMPLETED, ValidationRun.Status.FAILED, ValidationRun.Status.CANCELLED}:
            break
        time.sleep(0.5)

    run.refresh_from_db()
    assert run.status == ValidationRun.Status.COMPLETED, run.error_message
    assert run.result['engine'] == ENGINE
    assert run.result['exploitability']['state'] == 'confirmed'
    assert Evidence.objects.filter(id=run.result['evidence_id'], finding=finding, source=ENGINE).exists()

    result_response = async_to_sync(validations.get_validation_result)(run.id, user={'user_id': str(user.id)})
    evidence_response = async_to_sync(validations.get_validation_evidence)(run.id, user={'user_id': str(user.id)})
    assert result_response.result['evidence_id'] == run.result['evidence_id']
    assert len(evidence_response) == 1
