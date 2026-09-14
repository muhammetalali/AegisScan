from __future__ import annotations

from asgiref.sync import async_to_sync, sync_to_async
from django.db import connections
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.routers import wstg as wstg_router
from fastapi_app.routers.reports import _build_payload, _make_csv
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
    return owner, outsider, project, scan


@pytest.mark.django_db
def test_project_coverage_is_canonical_observation_only_and_rejects_tampered_lineage():
    _, _, project, _ = _fixture_project()

    coverage = build_wstg_project_coverage(project)

    assert coverage['contract_version'] == '1.0'
    assert coverage['methodology'] == 'WSTG'
    assert coverage['methodology_version'] == '4.2'
    assert coverage['source'] == 'postgresql'
    assert coverage['claim_policy'] == 'observation-only'
    assert coverage['completion_claim_allowed'] is False
    assert coverage['finding_state_authority'] == 'governed-finding-confirmation'
    assert coverage['summary']['total_tests'] == 97
    assert coverage['summary']['observed_tests'] == 5
    assert coverage['summary']['trusted_evidence_records'] == 1
    assert coverage['summary']['trusted_finding_records'] == 1
    assert coverage['summary']['rejected_lineage_records'] == 1
    assert coverage['summary']['states']['observed'] == 5
    assert coverage['summary']['states']['manual_required'] == 21
    assert coverage['summary']['states']['blocked_native_gap'] == 5
    assert coverage['summary']['states']['inconclusive'] == 1

    rows = {item['wstg_id']: item for item in coverage['tests']}
    assert rows['WSTG-v42-INFO-02']['state'] == 'observed'
    assert rows['WSTG-v42-INFO-02']['evidence_records'] == 1
    assert rows['WSTG-v42-INFO-02']['finding_records'] == 1
    assert rows['WSTG-v42-INFO-02']['capability_ids'] == ['network.nmap']
    assert rows['WSTG-v42-IDNT-02']['state'] == 'manual_required'
    assert rows['WSTG-v42-INPV-04']['state'] == 'blocked_native_gap'
    assert rows['WSTG-v42-CLNT-08']['state'] == 'inconclusive'
    assert all(item['completion_claim_allowed'] is False for item in coverage['tests'])


@pytest.mark.django_db
def test_wstg_report_projection_reuses_same_coverage_contract():
    _, _, project, _ = _fixture_project()

    payload = async_to_sync(_build_payload)(str(project.id), None, 'wstg')

    assert set(payload) == {'project', 'wstg_coverage'}
    assert payload['wstg_coverage']['summary']['observed_tests'] == 5
    assert payload['wstg_coverage']['completion_claim_allowed'] is False
    csv_bytes = _make_csv(payload)
    csv_text = csv_bytes.decode('utf-8')
    assert 'WSTG-v42-INFO-02' in csv_text
    assert 'observation-only' not in csv_text
    assert 'observed' in csv_text


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
