from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from django.core.exceptions import ValidationError
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from enterprise.detection_models import DetectionEvent, DetectionPublication, DetectionRevision, DetectionRule, DetectionValidation
from enterprise.models import ExternalIntegration, Organization, OrganizationMembership, TenantProject
from fastapi_app.core import dependencies as core_dependencies
from fastapi_app.main import app
from fastapi_app.services.detection_engineering import (
    DetectionEngineeringError,
    compile_spec,
    create_revision,
    publish_revision,
    validate_revision,
)


pytestmark = pytest.mark.django_db(transaction=True)


class _CaptureHandler(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length)
        type(self).requests.append({'path': self.path, 'body': json.loads(raw.decode('utf-8')), 'authorization': self.headers.get('Authorization')})
        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(b'{"accepted":true}')

    def log_message(self, format, *args):
        return


@pytest.fixture
def detection_fixture(transactional_db):
    user = User.objects.create_user(
        email='detection-engineering@example.invalid', password='Strong-Test-Password-123!',
        first_name='Detection', last_name='Engineer',
    )
    project = Project.objects.create(name='Detection Engineering Reality', slug='detection-engineering-reality', owner=user)
    asset = Asset.objects.create(
        project=project, name='Detection Target', slug='detection-target', type=Asset.Type.IP_ADDRESS,
        environment=Asset.Environment.PRODUCTION, criticality=Asset.Criticality.HIGH,
        configuration={'host': 'detection-target', 'authorized': True}, owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=True, target_snapshot='detection-target', reason='Detection reality authorization',
    )
    scan = Scan.objects.create(
        project=project, name='Detection Source Scan', scan_type=Scan.Type.NETWORK, depth=Scan.Depth.QUICK,
        asset=asset, engines=['nmap'], config={'target': 'detection-target'}, initiated_by=user,
        authorization_decision=authorization,
    )
    finding = Vulnerability.objects.create(
        scan=scan, project=project, asset=asset, title='PowerShell execution',
        description='Evidence-backed source finding for detection engineering.', severity=Vulnerability.Severity.HIGH,
        status=Vulnerability.Status.OPEN, confidence=Vulnerability.Confidence.CONFIRMED,
        source_engine='nmap', raw_data={'process': 'powershell.exe'},
    )
    evidence = Evidence.objects.create(
        scan=scan, asset=asset, finding=finding, source='reality', evidence_type='validation_output',
        raw_output='{"process":{"name":"powershell.exe"}}', collected_by=user,
        metadata={'finding_present': True},
    )
    organization = Organization.objects.create(name='Detection Tenant', slug='detection-tenant', owner=user, is_active=True)
    membership = OrganizationMembership.objects.create(
        organization=organization, user=user, role=OrganizationMembership.Role.MANAGER, is_active=True,
    )
    TenantProject.objects.create(organization=organization, project=project)
    app.dependency_overrides[core_dependencies.get_current_user] = lambda: {'user_id': str(user.id), 'is_staff': True}
    client = TestClient(app)
    try:
        yield client, user, project, finding, evidence, organization, membership
    finally:
        app.dependency_overrides.clear()
        client.close()


def _spec():
    return {
        'logsource': 'endpoint.process',
        'condition': 'all',
        'match': [
            {'field': 'process.name', 'operator': 'equals', 'value': 'powershell.exe'},
            {'field': 'process.command_line', 'operator': 'contains', 'value': '-enc'},
        ],
        'severity': 'high',
        'attack_techniques': ['T1059.001'],
        'description': 'Detect encoded PowerShell execution.',
    }


def _telemetry():
    return [
        {'process': {'name': 'powershell.exe', 'command_line': 'powershell.exe -enc AAAA'}, 'host': 'ws-01'},
        {'process': {'name': 'cmd.exe', 'command_line': 'cmd.exe /c whoami'}, 'host': 'ws-02'},
    ]


def _revision(user, project, finding, evidence):
    return create_revision(
        project_id=str(project.id), user_id=str(user.id), slug='encoded-powershell', title='Encoded PowerShell',
        description='Governed endpoint detection.', finding_id=str(finding.id), evidence_id=str(evidence.id), spec=_spec(),
    )


def test_compiler_emits_all_supported_targets():
    compiled = compile_spec(_spec())
    assert set(compiled) == {'splunk', 'elastic_kql', 'sentinel_kql', 'qradar_aql'}
    assert 'powershell.exe' in compiled['splunk']
    assert 'powershell.exe' in compiled['elastic_kql']
    assert 'powershell.exe' in compiled['sentinel_kql']
    assert compiled['qradar_aql'].startswith('SELECT * FROM events WHERE ')


def test_revision_has_finding_evidence_attack_lineage_and_exact_replay(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    first = _revision(user, project, finding, evidence)
    second = _revision(user, project, finding, evidence)
    assert first.replayed is False
    assert second.replayed is True
    assert first.revision.id == second.revision.id
    assert first.revision.source_finding_id == finding.id
    assert first.revision.source_evidence_id == evidence.id
    assert first.revision.attack_techniques == ['T1059.001']
    assert len(first.revision.content_sha256) == 64
    assert DetectionRevision.objects.filter(rule=first.revision.rule).count() == 1
    assert DetectionEvent.objects.filter(rule=first.revision.rule, event_type='revision.created').count() == 1


def test_invalid_attack_technique_is_rejected(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    spec = _spec(); spec['attack_techniques'] = ['NOT-ATTACK']
    with pytest.raises(DetectionEngineeringError, match='ATT&CK'):
        create_revision(
            project_id=str(project.id), user_id=str(user.id), slug='invalid-technique', title='Invalid Technique',
            description='', finding_id=str(finding.id), evidence_id=str(evidence.id), spec=spec,
        )


def test_validation_executes_against_telemetry_and_replays(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _revision(user, project, finding, evidence).revision
    first = validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id), telemetry=_telemetry(), minimum_matches=1,
    )
    second = validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id), telemetry=list(reversed(_telemetry())), minimum_matches=1,
    )
    assert first.validation.status == DetectionValidation.Status.PASSED
    assert first.validation.matched_count == 1
    assert first.replayed is False
    assert second.replayed is True
    assert first.validation.id == second.validation.id
    revision.rule.refresh_from_db()
    assert revision.rule.state == DetectionRule.State.VALIDATED
    assert DetectionEvent.objects.filter(rule=revision.rule, event_type='validation.completed').count() == 1


def test_publication_requires_passed_validation(detection_fixture):
    _client, user, project, finding, evidence, organization, _membership = detection_fixture
    revision = _revision(user, project, finding, evidence).revision
    integration = ExternalIntegration.objects.create(
        organization=organization, kind=ExternalIntegration.Kind.ELASTIC, name='No Validation Elastic',
        base_url='http://127.0.0.1:9', config={'index': 'detections'}, created_by=user,
    )
    with pytest.raises(DetectionEngineeringError, match='passed telemetry validation'):
        publish_revision(
            revision_id=str(revision.id), integration_id=str(integration.id), project_id=str(project.id), user_id=str(user.id),
        )


def test_publication_uses_real_http_transport_and_exact_replay(detection_fixture):
    _client, user, project, finding, evidence, organization, _membership = detection_fixture
    revision = _revision(user, project, finding, evidence).revision
    validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id), telemetry=_telemetry(), minimum_matches=1,
    )
    _CaptureHandler.requests = []
    server = ThreadingHTTPServer(('127.0.0.1', 0), _CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        integration = ExternalIntegration.objects.create(
            organization=organization, kind=ExternalIntegration.Kind.ELASTIC, name='Reality Elastic',
            base_url=f'http://127.0.0.1:{server.server_port}', config={'index': 'detections'}, created_by=user,
        )
        first = publish_revision(
            revision_id=str(revision.id), integration_id=str(integration.id), project_id=str(project.id), user_id=str(user.id),
        )
        second = publish_revision(
            revision_id=str(revision.id), integration_id=str(integration.id), project_id=str(project.id), user_id=str(user.id),
        )
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    assert first.replayed is False
    assert second.replayed is True
    assert first.publication.id == second.publication.id
    assert first.publication.transport_status == 201
    assert len(_CaptureHandler.requests) == 1
    request = _CaptureHandler.requests[0]
    assert request['path'] == '/detections/_doc'
    assert request['body']['type'] == 'aegisscan.detection.package'
    assert request['body']['attack_techniques'] == ['T1059.001']
    assert request['body']['source_finding_id'] == str(finding.id)
    assert DetectionPublication.objects.filter(revision=revision).count() == 1
    revision.rule.refresh_from_db(); assert revision.rule.state == DetectionRule.State.PUBLISHED


def test_analyst_can_author_but_cannot_publish(detection_fixture):
    _client, user, project, finding, evidence, organization, membership = detection_fixture
    membership.role = OrganizationMembership.Role.ANALYST; membership.save(update_fields=['role'])
    revision = _revision(user, project, finding, evidence).revision
    validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id), telemetry=_telemetry(), minimum_matches=1,
    )
    integration = ExternalIntegration.objects.create(
        organization=organization, kind=ExternalIntegration.Kind.ELASTIC, name='Analyst Elastic',
        base_url='http://127.0.0.1:9', config={'index': 'detections'}, created_by=user,
    )
    with pytest.raises(PermissionError, match='does not permit'):
        publish_revision(
            revision_id=str(revision.id), integration_id=str(integration.id), project_id=str(project.id), user_id=str(user.id),
        )


def test_append_only_detection_evidence_cannot_be_mutated(detection_fixture):
    _client, user, project, finding, evidence, _organization, _membership = detection_fixture
    revision = _revision(user, project, finding, evidence).revision
    validation = validate_revision(
        revision_id=str(revision.id), project_id=str(project.id), user_id=str(user.id), telemetry=_telemetry(), minimum_matches=1,
    ).validation
    with pytest.raises(ValidationError):
        DetectionRevision.objects.filter(pk=revision.id).update(version=99)
    with pytest.raises(ValidationError):
        validation.delete()


def test_strict_api_contract_and_registered_route(detection_fixture):
    client, _user, project, finding, evidence, _organization, _membership = detection_fixture
    body = {
        'slug': 'api-detection', 'title': 'API Detection', 'description': 'Strict API detection',
        'finding_id': str(finding.id), 'evidence_id': str(evidence.id), 'spec': _spec(), 'unexpected': True,
    }
    response = client.post(f'/api/v1/enterprise-gap/detections/projects/{project.id}/rules', json=body)
    assert response.status_code == 422
    paths = app.openapi()['paths']
    assert f'/api/v1/enterprise-gap/detections/projects/{{project_id}}/rules' in paths
