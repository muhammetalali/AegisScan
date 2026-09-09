from __future__ import annotations

import json

import pytest

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.offensive_validation import ENGINE
from fastapi_app.tasks.offensive_validation_tasks import validate_offensive_finding


def _fixture_finding():
    user = User.objects.create_user(email='offensive-task-owner@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Offensive Task', slug='offensive-task', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Task authorized web app',
        slug='task-authorized-web-app',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'http://127.0.0.1/task-login'},
    )
    decision = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='http://127.0.0.1/task-login',
        reason='task integration authorized endpoint',
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='Task browser finding source',
        scan_type=Scan.Type.URL,
        engines=['browser.dom-snapshot'],
        config={'target': 'http://127.0.0.1/task-login'},
        initiated_by=user,
        status=Scan.Status.COMPLETED,
    )
    raw_browser = json.dumps({
        'schema': 'aegis.browser-security.v1',
        'target_url': 'http://127.0.0.1/task-login',
        'observations': [{
            'kind': 'browser-dom-security-snapshot',
            'insecure_form_actions': ['http://127.0.0.1/task-login'],
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
        title='Form submits data over cleartext HTTP from task',
        description='Browser evidence detected cleartext form transport.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN,
        confidence=Vulnerability.Confidence.UNVERIFIED,
        category='browser-security',
        cwe_id='CWE-319',
        tags=['browser.insecure-form-action'],
        url='http://127.0.0.1/task-login',
        source_engine='aegis-browser-security',
        raw_data={
            'rule_id': 'browser.insecure-form-action',
            'affected_urls': ['http://127.0.0.1/task-login'],
        },
    )
    return user, finding, decision


@pytest.mark.django_db
def test_offensive_validation_task_runs_and_redelivery_is_idempotent(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    user, finding, decision = _fixture_finding()
    run = ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type='url',
        target_value='http://127.0.0.1/task-login',
        scope=str(finding.project_id),
        profile='standard',
        engines=[ENGINE],
        authorized=True,
        authorization_decision=decision,
        status=ValidationRun.Status.QUEUED,
    )

    first = validate_offensive_finding.run(str(run.id))
    run.refresh_from_db()
    assert run.status == ValidationRun.Status.COMPLETED
    assert first['engine'] == ENGINE
    assert first['exploitability']['state'] == 'confirmed'
    assert Evidence.objects.filter(id=first['evidence_id'], finding=finding, source=ENGINE).exists()

    second = validate_offensive_finding.run(str(run.id))
    assert second['redelivered'] is True
    assert second['evidence_id'] == first['evidence_id']
    assert Evidence.objects.filter(finding=finding, source=ENGINE).count() == 1


@pytest.mark.django_db
def test_offensive_validation_task_preserves_cancelled_terminal_state(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    user, finding, decision = _fixture_finding()
    run = ValidationRun.objects.create(
        user=user,
        finding=finding,
        target_type='url',
        target_value='http://127.0.0.1/task-login',
        scope=str(finding.project_id),
        profile='standard',
        engines=[ENGINE],
        authorized=True,
        authorization_decision=decision,
        status=ValidationRun.Status.CANCELLED,
    )

    result = validate_offensive_finding.run(str(run.id))
    assert result['status'] == ValidationRun.Status.CANCELLED
    assert result['redelivered'] is True
    assert Evidence.objects.filter(finding=finding, source=ENGINE).count() == 0
