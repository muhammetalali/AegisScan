from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from assets.models import Asset, AssetRelationship
from enterprise.models import AttackPath
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.main import app

pytestmark = pytest.mark.django_db(transaction=True)


def test_attack_path_reads_real_graph_and_persists_discovered_path():
    user = User.objects.create_user(email='attack-path-e2e@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Attack Path E2E', slug='attack-path-e2e', owner=user)
    source = Asset.objects.create(project=project, name='Internet Gateway', slug='gateway', type=Asset.Type.WEBSITE, configuration={'internet_exposed': True})
    middle = Asset.objects.create(project=project, name='Application', slug='application', type=Asset.Type.API_ENDPOINT)
    target = Asset.objects.create(project=project, name='Sensitive Service', slug='sensitive-service', type=Asset.Type.CLOUD_RESOURCE, criticality=Asset.Criticality.CRITICAL)
    AssetRelationship.objects.create(project=project, source=source, target=middle, relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO)
    AssetRelationship.objects.create(project=project, source=middle, target=target, relationship_type=AssetRelationship.RelationshipType.CONNECTS_TO)
    scan = Scan.objects.create(project=project, name='Attack Path Scan', scan_type=Scan.Type.FULL_VALIDATION, initiated_by=user, engines=['nmap'])
    Vulnerability.objects.create(
        project=project, scan=scan, asset=target, title='Critical test finding', description='Controlled attack path evidence',
        severity=Vulnerability.Severity.CRITICAL, status=Vulnerability.Status.OPEN, risk_score=9.0, source_engine='nmap',
    )

    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    try:
        client = TestClient(app)
        graph = client.get(f'/api/v1/attack-path/projects/{project.id}')
        assert graph.status_code == 200, graph.text
        graph_payload = graph.json()
        assert graph_payload['source'] == 'postgresql'
        assert len(graph_payload['nodes']) == 3
        assert len(graph_payload['edges']) == 2

        response = client.post(
            f'/api/v1/attack-path/projects/{project.id}/analyze',
            json={'source_asset_id': str(source.id), 'target_asset_id': str(target.id), 'max_hops': 4},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['paths']
    assert payload['persisted_attack_path_ids']
    persisted = AttackPath.objects.get(pk=payload['persisted_attack_path_ids'][0])
    assert persisted.project_id == project.id
    assert persisted.steps == payload['paths'][0]['nodes']
    assert persisted.risk_score == payload['paths'][0]['risk_score']
