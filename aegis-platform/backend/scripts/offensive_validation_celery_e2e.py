from __future__ import annotations

import json
import os
import time
from uuid import uuid4

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

import django

django.setup()

from asgiref.sync import async_to_sync

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.routers import validations
from fastapi_app.services.offensive_validation import ENGINE


def main() -> None:
    suffix = uuid4().hex[:10]
    email = f'offensive-celery-ci-{suffix}@example.invalid'
    user = User.objects.create_user(email=email, password='Strong-Test-Password-123!')
    project = Project.objects.create(name=f'Offensive Celery CI {suffix}', slug=f'offensive-celery-ci-{suffix}', owner=user)
    target = 'http://127.0.0.1/celery-login'
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='CI authorized web app',
        slug=f'ci-authorized-web-app-{suffix}',
        type=Asset.Type.WEBSITE,
        configuration={'url': target},
    )
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=target,
        reason='redis celery e2e authorized endpoint',
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='CI browser finding source',
        scan_type=Scan.Type.URL,
        engines=['browser.dom-snapshot'],
        config={'target': target},
        initiated_by=user,
        status=Scan.Status.COMPLETED,
    )
    Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='browser-security',
        evidence_type='browser_dom_snapshot',
        raw_output=json.dumps({
            'schema': 'aegis.browser-security.v1',
            'target_url': target,
            'observations': [{
                'kind': 'browser-dom-security-snapshot',
                'insecure_form_actions': [target],
                'mixed_content_urls': [],
            }],
        }, sort_keys=True),
        metadata={'schema': 'aegis.browser-security.v1'},
        collected_by=user,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Form submits data over cleartext HTTP from Redis Celery worker',
        description='Browser evidence detected cleartext form transport.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.UNVERIFIED,
        category='browser-security',
        cwe_id='CWE-319',
        tags=['browser.insecure-form-action'],
        url=target,
        source_engine='aegis-browser-security',
        raw_data={'rule_id': 'browser.insecure-form-action', 'affected_urls': [target]},
    )

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
    assert run.authorization_decision_id == decision.id
    assert run.result['engine'] == ENGINE
    assert run.result['exploitability']['state'] == 'confirmed'
    assert run.result['runtime']['live_session_opened'] is False
    assert run.result['runtime']['unrestricted_shell_opened'] is False
    evidence = Evidence.objects.get(id=run.result['evidence_id'], finding=finding, source=ENGINE)
    assert evidence.metadata['validation_run_id'] == str(run.id)
    assert evidence.metadata['authorization_decision_id'] == str(decision.id)

    result_response = async_to_sync(validations.get_validation_result)(run.id, user={'user_id': str(user.id)})
    evidence_response = async_to_sync(validations.get_validation_evidence)(run.id, user={'user_id': str(user.id)})
    assert result_response.result['evidence_id'] == str(evidence.id)
    assert [item.id for item in evidence_response] == [str(evidence.id)]
    print('offensive-validation-redis-celery-e2e-ok', run.id, evidence.id)


if __name__ == '__main__':
    main()
