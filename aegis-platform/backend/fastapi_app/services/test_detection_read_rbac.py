from __future__ import annotations

import pytest

from enterprise.models import OrganizationMembership
from fastapi_app.services.test_detection_engineering import detection_fixture, _revision, _spec


pytestmark = pytest.mark.django_db(transaction=True)


def test_detection_rule_reads_require_active_tenant_membership_and_viewer_is_read_only(detection_fixture):
    client, user, project, finding, evidence, _organization, membership = detection_fixture
    _revision(user, project, finding, evidence)
    url = f'/api/v1/enterprise-gap/detections/projects/{project.id}/rules'

    allowed = client.get(url)
    assert allowed.status_code == 200
    assert len(allowed.json()) == 1

    membership.is_active = False
    membership.save(update_fields=['is_active'])
    denied = client.get(url)
    assert denied.status_code == 403

    membership.is_active = True
    membership.role = OrganizationMembership.Role.VIEWER
    membership.save(update_fields=['is_active', 'role'])
    viewer_read = client.get(url)
    assert viewer_read.status_code == 200
    assert len(viewer_read.json()) == 1

    author_attempt = client.post(
        url,
        json={
            'slug': 'viewer-cannot-author',
            'title': 'Viewer Cannot Author',
            'description': 'Tenant viewer read-only enforcement.',
            'finding_id': str(finding.id),
            'evidence_id': str(evidence.id),
            'spec': _spec(),
        },
    )
    assert author_attempt.status_code == 403
