from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.native_finding_projection import project_native_findings, sync_scan_finding_counts


@pytest.mark.django_db
def test_cloud_findings_and_evidence_are_resource_stable_and_idempotent():
    user = get_user_model().objects.create_user(email='cloud-findings@example.test', password='CloudFindings-123!')
    project = Project.objects.create(name='Cloud Findings', slug='cloud-findings', owner=user)
    target = 'aws://123456789012'
    asset = Asset.objects.create(
        project=project,
        name='Authorized AWS account',
        slug='authorized-aws-account',
        type=Asset.Type.CLOUD_RESOURCE,
        owner=user,
        configuration={'target': target},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=target,
        reason='CI authorized cloud account fixture',
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        authorization_decision=authorization,
        name='Cloud posture',
        scan_type=Scan.Type.FULL_VALIDATION,
        engines=['aegis-cloud-security'],
        initiated_by=user,
    )
    normalized = {
        'schema': 'aegis.native-observations.v1',
        'count': 2,
        'observations': [
            {
                'kind': 'cloud-security-finding',
                'provider': 'aws',
                'rule_id': 'cloud.aws.security-group.world-admin-or-all',
                'title': 'World-open SSH A',
                'description': 'Security group A exposes SSH to the Internet.',
                'severity': 'high',
                'confidence': 'high',
                'remediation': 'Restrict source CIDRs.',
                'resource_kind': 'aws.ec2.security-group',
                'resource_name': 'sg-a',
                'location': 'aws://ec2/us-east-1/security-group/sg-a',
            },
            {
                'kind': 'cloud-security-finding',
                'provider': 'aws',
                'rule_id': 'cloud.aws.security-group.world-admin-or-all',
                'title': 'World-open SSH B',
                'description': 'Security group B exposes SSH to the Internet.',
                'severity': 'high',
                'confidence': 'high',
                'remediation': 'Restrict source CIDRs.',
                'resource_kind': 'aws.ec2.security-group',
                'resource_name': 'sg-b',
                'location': 'aws://ec2/us-east-1/security-group/sg-b',
            },
        ],
    }

    first_findings, first_evidence = project_native_findings(
        scan=scan,
        capability_id='cloud.read-only-posture',
        source_engine='aegis-cloud-security',
        target=target,
        normalized=normalized,
    )
    assert len(first_findings) == 2
    assert len(set(first_findings)) == 2
    assert len(first_evidence) == 2

    second_findings, second_evidence = project_native_findings(
        scan=scan,
        capability_id='cloud.read-only-posture',
        source_engine='aegis-cloud-security',
        target=target,
        normalized=normalized,
    )
    assert second_findings == first_findings
    assert second_evidence == first_evidence
    assert Vulnerability.objects.filter(scan=scan, category='cloud-security').count() == 2
    assert Evidence.objects.filter(scan=scan, evidence_type='finding_observation').count() == 2

    sync_scan_finding_counts(scan)
    scan.save(update_fields=['findings_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count'])
    scan.refresh_from_db()
    assert scan.findings_count == 2
    assert scan.high_count == 2
    for finding in Vulnerability.objects.filter(scan=scan):
        assert finding.raw_data['capability_id'] == 'cloud.read-only-posture'
        assert finding.raw_data['provider'] == 'aws'
        assert finding.raw_data['location'].startswith('aws://ec2/')
