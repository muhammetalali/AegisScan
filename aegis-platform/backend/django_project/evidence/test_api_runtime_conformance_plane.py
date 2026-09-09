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
def test_api_runtime_findings_persist_and_redeliver_without_duplicates():
    user = get_user_model().objects.create_user(email='api-runtime@example.test', password='ApiRuntime-123!')
    project = Project.objects.create(name='API Runtime', slug='api-runtime', owner=user)
    target = 'https://api.example.test'
    asset = Asset.objects.create(
        project=project,
        name='Runtime API',
        slug='runtime-api',
        type=Asset.Type.API_ENDPOINT,
        owner=user,
        configuration={'url': target},
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='OpenAPI runtime conformance',
        scan_type=Scan.Type.URL,
        engines=['aegis-api-runtime-conformance'],
        initiated_by=user,
    )
    normalized = {
        'schema': 'aegis.native-observations.v1',
        'count': 2,
        'observations': [
            {
                'kind': 'api-runtime-security-finding',
                'rule_id': 'api.runtime.response-shape-mismatch',
                'title': 'Runtime JSON response violates declared schema constraints',
                'description': 'GET /items returned a response missing a required property.',
                'severity': 'medium',
                'confidence': 'high',
                'remediation': 'Align response serialization with the contract.',
                'location': 'paths./items.get',
                'method': 'GET',
                'path': '/items',
                'status': 200,
                'validation_errors': ['$: missing required property id'],
            },
            {
                'kind': 'api-runtime-security-finding',
                'rule_id': 'api.runtime.required-query-not-enforced',
                'title': 'Required query parameter was not enforced at runtime',
                'description': 'GET /items accepted a request without the required limit parameter.',
                'severity': 'low',
                'confidence': 'medium',
                'remediation': 'Enforce required query parameters.',
                'location': 'paths./items.get.parameters.limit',
                'method': 'GET',
                'path': '/items',
                'parameter': 'limit',
                'status': 200,
            },
        ],
    }

    first_findings, first_evidence = project_native_findings(
        scan=scan,
        capability_id='api.openapi-runtime-conformance',
        source_engine='aegis-api-runtime-conformance',
        target=target,
        normalized=normalized,
    )
    assert len(first_findings) == 2
    assert len(set(first_findings)) == 2
    assert len(first_evidence) == 2
    assert Vulnerability.objects.filter(scan=scan, category='api-runtime-security').count() == 2
    assert Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count() == 2

    # A later delivery with a different observed status must update the same
    # semantic finding rather than create a new workflow object.
    normalized['observations'][1]['status'] = 204
    second_findings, second_evidence = project_native_findings(
        scan=scan,
        capability_id='api.openapi-runtime-conformance',
        source_engine='aegis-api-runtime-conformance',
        target=target,
        normalized=normalized,
    )
    assert second_findings == first_findings
    assert second_evidence == first_evidence
    assert Vulnerability.objects.filter(scan=scan, category='api-runtime-security').count() == 2
    assert Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count() == 2

    sync_scan_finding_counts(scan)
    scan.save(update_fields=['findings_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count'])
    scan.refresh_from_db()
    assert scan.findings_count == 2
    assert scan.medium_count == 1
    assert scan.low_count == 1

    query_finding = Vulnerability.objects.get(scan=scan, raw_data__rule_id='api.runtime.required-query-not-enforced')
    assert query_finding.raw_data['parameter'] == 'limit'
    assert query_finding.raw_data['status'] == 204
    assert query_finding.raw_data['capability_id'] == 'api.openapi-runtime-conformance'
    assert 'api-runtime-security' in query_finding.tags
