from __future__ import annotations

import urllib.parse

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.offensive_validation import (
    ENGINE,
    HTTPProbeResponse,
    ProbeRequest,
    build_validation_plan,
    run_offensive_validation,
)


@pytest.fixture
def finding(db):
    User = get_user_model()
    user = User.objects.create_user(
        email='offensive-validation@example.test',
        password='OffensiveValidation-123!',
        first_name='Offensive',
        last_name='Validation',
    )
    project = Project.objects.create(name='Offensive Validation', slug='offensive-validation', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='Lab Web App',
        slug='lab-web-app',
        type=Asset.Type.WEBSITE,
        owner=user,
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='Browser + Offensive Validation',
        scan_type=Scan.Type.URL,
        engines=['aegis-browser-security', ENGINE],
        initiated_by=user,
    )
    finding = Vulnerability.objects.create(
        scan=scan,
        project=project,
        asset=asset,
        title='Reflected XSS candidate in search endpoint',
        description='The response appears to reflect attacker-controlled input.',
        severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.ACCEPTED_RISK,
        confidence=Vulnerability.Confidence.UNVERIFIED,
        category='xss',
        cwe_id='CWE-79',
        tags=['xss', 'aegisscan-native'],
        url='http://127.0.0.1/search',
        parameter='q',
        source_engine='aegis-browser-security',
        raw_data={'rule_id': 'browser.reflection-candidate', 'target_url': 'http://127.0.0.1/search'},
    )
    return finding


def test_build_validation_plan_is_typed_and_contains_no_shell_payloads(finding, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    plan = build_validation_plan(finding, token='aegis-fixed-token')
    assert [item.kind for item in plan] == ['http-reachability', 'reflected-token']
    assert all(item.method in {'GET', 'HEAD'} for item in plan)
    assert all('meterpreter' not in item.url.lower() for item in plan)
    assert all('/bin/sh' not in item.url.lower() for item in plan)


def test_offensive_validation_persists_evidence_and_confirms_exploitability_without_governance_override(finding, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    sensitive_fixture_value = 'raw-secret-value-that-must-not-leak'
    seen: list[ProbeRequest] = []

    def fake_http_client(probe: ProbeRequest) -> HTTPProbeResponse:
        seen.append(probe)
        if probe.kind == 'http-reachability':
            return HTTPProbeResponse(status=200, headers={'server': 'fixture'}, body='', final_url=probe.url)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(probe.url).query)
        marker = query.get('aegis_validation_token', [''])[0]
        return HTTPProbeResponse(
            status=200,
            headers={'content-type': 'text/html'},
            body=f'<html><body>reflected:{marker}:{sensitive_fixture_value}</body></html>',
            final_url=probe.url,
        )

    result = run_offensive_validation(
        finding=finding,
        actor=finding.scan.initiated_by,
        http_client=fake_http_client,
        secrets_to_redact=(sensitive_fixture_value,),
    )

    assert result['schema'] == 'aegis.offensive-validation.v1'
    assert result['engine'] == ENGINE
    assert result['exploitability']['state'] == 'confirmed'
    assert result['exploitability']['proven_count'] == 1
    assert result['runtime'] == {
        'live_session_opened': False,
        'unrestricted_shell_opened': False,
        'raw_secret_material_stored': False,
    }
    assert [item.kind for item in seen] == ['http-reachability', 'reflected-token']

    run = ValidationRun.objects.get(id=result['validation_run_id'])
    assert run.status == ValidationRun.Status.COMPLETED
    assert run.authorized is True
    assert run.engines == [ENGINE]
    assert run.result['exploitability']['state'] == 'confirmed'

    evidence = Evidence.objects.get(id=result['evidence_id'])
    assert evidence.finding_id == finding.id
    assert evidence.source == ENGINE
    assert evidence.evidence_type == 'exploitability_proof'
    assert evidence.sha256
    assert evidence.metadata['validation_run_id'] == str(run.id)
    assert sensitive_fixture_value not in evidence.raw_output
    assert '[REDACTED]' in evidence.raw_output

    finding.refresh_from_db()
    assert finding.validation_status == 'confirmed'
    assert finding.confidence == Vulnerability.Confidence.CONFIRMED
    assert finding.exploitability >= 0.9
    assert finding.status == Vulnerability.Status.ACCEPTED_RISK
    assert finding.verified_evidence_count >= 1

    # Redelivery is idempotent for evidence identity and does not reset governance state.
    second = run_offensive_validation(
        finding=finding,
        actor=finding.scan.initiated_by,
        http_client=fake_http_client,
        validation_run=run,
        secrets_to_redact=(sensitive_fixture_value,),
    )
    assert second['validation_run_id'] == str(run.id)
    assert second['evidence_id'] == result['evidence_id']
    finding.refresh_from_db()
    assert finding.status == Vulnerability.Status.ACCEPTED_RISK


def test_browser_transport_finding_can_be_validated_from_existing_evidence_without_network(finding, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    finding.title = 'Form submits data over cleartext HTTP'
    finding.category = 'browser-security'
    finding.cwe_id = 'CWE-319'
    finding.tags = ['browser.insecure-form-action']
    finding.raw_data = {'rule_id': 'browser.insecure-form-action', 'affected_urls': ['http://127.0.0.1/login']}
    finding.save(update_fields=['title', 'category', 'cwe_id', 'tags', 'raw_data'])
    calls: list[ProbeRequest] = []

    def fake_http_client(probe: ProbeRequest) -> HTTPProbeResponse:
        calls.append(probe)
        return HTTPProbeResponse(status=200, headers={}, body='', final_url=probe.url)

    result = run_offensive_validation(
        finding=finding,
        actor=finding.scan.initiated_by,
        http_client=fake_http_client,
    )
    assert result['exploitability']['state'] == 'confirmed'
    assert any(item['kind'] == 'semantic-browser-transport' for item in result['probes'])
    assert [item.kind for item in calls] == ['http-reachability']


def test_live_session_payloads_are_rejected_before_evidence_is_stored(finding, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    finding.raw_data = {'payload': 'meterpreter reverse shell'}
    finding.save(update_fields=['raw_data'])

    with pytest.raises(ValueError, match='Live shell/session payloads'):
        run_offensive_validation(
            finding=finding,
            actor=finding.scan.initiated_by,
            http_client=lambda probe: HTTPProbeResponse(status=200, headers={}, body='', final_url=probe.url),
        )
    assert ValidationRun.objects.count() == 0
    assert Evidence.objects.filter(source=ENGINE).count() == 0
