from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.native_finding_projection import project_native_findings, sync_scan_finding_counts


@pytest.mark.django_db
def test_api_schema_findings_persist_per_location_and_redeliver_idempotently():
    user = get_user_model().objects.create_user(email='api-schema@example.test', password='ApiSchema-123!')
    project = Project.objects.create(name='API Schema', slug='api-schema', owner=user)
    target = 'https://api.example.test'
    asset = Asset.objects.create(
        project=project,
        name='Authorized API',
        slug='authorized-api',
        type=Asset.Type.API_ENDPOINT,
        owner=user,
        configuration={'url': target},
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='OpenAPI contract security',
        scan_type=Scan.Type.URL,
        engines=['aegis-api-schema-security'],
        initiated_by=user,
    )
    normalized = {
        'schema': 'aegis.native-observations.v1',
        'count': 2,
        'observations': [
            {
                'kind': 'api-schema-security-finding',
                'rule_id': 'api.openapi.undefined-security-scheme',
                'title': 'Undefined security scheme A',
                'description': 'GET /a references an undefined security scheme.',
                'severity': 'medium',
                'confidence': 'high',
                'remediation': 'Define the scheme.',
                'location': 'paths./a.get.security',
                'method': 'GET',
                'path': '/a',
            },
            {
                'kind': 'api-schema-security-finding',
                'rule_id': 'api.openapi.undefined-security-scheme',
                'title': 'Undefined security scheme B',
                'description': 'GET /b references an undefined security scheme.',
                'severity': 'medium',
                'confidence': 'high',
                'remediation': 'Define the scheme.',
                'location': 'paths./b.get.security',
                'method': 'GET',
                'path': '/b',
            },
        ],
    }

    first_findings, first_evidence = project_native_findings(
        scan=scan,
        capability_id='api.openapi-contract-security',
        source_engine='aegis-api-schema-security',
        target=target,
        normalized=normalized,
    )
    assert len(first_findings) == 2
    assert len(set(first_findings)) == 2
    assert len(first_evidence) == 2
    assert Vulnerability.objects.filter(scan=scan, category='api-security').count() == 2
    assert Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count() == 2

    second_findings, second_evidence = project_native_findings(
        scan=scan,
        capability_id='api.openapi-contract-security',
        source_engine='aegis-api-schema-security',
        target=target,
        normalized=normalized,
    )
    assert second_findings == first_findings
    assert second_evidence == first_evidence
    assert Vulnerability.objects.filter(scan=scan, category='api-security').count() == 2
    assert Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count() == 2

    sync_scan_finding_counts(scan)
    scan.save(update_fields=['findings_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count'])
    scan.refresh_from_db()
    assert scan.findings_count == 2
    assert scan.medium_count == 2
    for finding in Vulnerability.objects.filter(scan=scan):
        assert finding.raw_data['capability_id'] == 'api.openapi-contract-security'
        assert finding.raw_data['location'] in {'paths./a.get.security', 'paths./b.get.security'}
        assert 'api-security' in finding.tags
