from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.native_finding_projection import (
    browser_finding_specs,
    project_native_findings,
    sync_scan_finding_counts,
)


NORMALIZED = {
    'schema': 'aegis.native-observations.v1',
    'count': 1,
    'observations': [{
        'kind': 'browser-dom-security-snapshot',
        'title': 'Checkout',
        'script_count': 1,
        'inline_script_count': 0,
        'iframe_count': 0,
        'form_count': 1,
        'password_field_count': 1,
        'meta_csp_present': False,
        'base_tag_present': False,
        'resource_host_count': 1,
        'third_party_resource_hosts': [],
        'mixed_content_urls': ['http://app.example.test/insecure.js'],
        'insecure_form_actions': ['http://app.example.test/login'],
        'link_rel_values': [],
    }],
}


def test_browser_finding_rules_only_emit_explicit_security_violations() -> None:
    specs = browser_finding_specs(NORMALIZED)
    assert [item.rule_id for item in specs] == ['browser.mixed-content', 'browser.insecure-form-action']
    assert specs[0].severity == 'medium'
    assert specs[1].severity == 'high'
    assert specs[0].cwe_id == 'CWE-319'
    assert specs[1].cwe_id == 'CWE-319'

    informational_only = {
        'observations': [{
            'kind': 'browser-dom-security-snapshot',
            'third_party_resource_hosts': ['cdn.example.test'],
            'iframe_count': 2,
            'inline_script_count': 3,
            'password_field_count': 1,
            'mixed_content_urls': [],
            'insecure_form_actions': [],
        }]
    }
    assert browser_finding_specs(informational_only) == []


@pytest.mark.django_db
def test_browser_finding_projection_is_idempotent_and_links_evidence() -> None:
    User = get_user_model()
    user = User.objects.create_user(
        email='browser-reality@example.test',
        password='BrowserRealityPassword-123!',
        first_name='Browser',
        last_name='Reality',
    )
    project = Project.objects.create(name='Browser Reality', slug='browser-reality', owner=user)
    asset = Asset.objects.create(
        project=project,
        name='Browser Fixture',
        slug='browser-fixture',
        type=Asset.Type.WEBSITE,
        owner=user,
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='Browser DOM Snapshot',
        scan_type=Scan.Type.URL,
        engines=['aegis-browser-security'],
        initiated_by=user,
    )

    first_ids, first_evidence = project_native_findings(
        scan=scan,
        capability_id='browser.dom-snapshot',
        source_engine='aegis-browser-security',
        target='https://app.example.test/login',
        normalized=NORMALIZED,
    )
    second_ids, second_evidence = project_native_findings(
        scan=scan,
        capability_id='browser.dom-snapshot',
        source_engine='aegis-browser-security',
        target='https://app.example.test/login',
        normalized=NORMALIZED,
    )
    sync_scan_finding_counts(scan)
    scan.save(update_fields=[
        'findings_count', 'critical_count', 'high_count', 'medium_count', 'low_count', 'info_count', 'updated_at'
    ])

    assert first_ids == second_ids
    assert first_evidence == second_evidence
    assert len(first_ids) == 2
    assert Vulnerability.objects.filter(scan=scan).count() == 2
    assert Evidence.objects.filter(scan=scan, finding__isnull=False).count() == 2
    assert set(Vulnerability.objects.filter(scan=scan).values_list('source_engine', flat=True)) == {'aegis-browser-security'}
    assert set(Vulnerability.objects.filter(scan=scan).values_list('severity', flat=True)) == {'medium', 'high'}

    scan.refresh_from_db()
    assert scan.findings_count == 2
    assert scan.high_count == 1
    assert scan.medium_count == 1

    for evidence in Evidence.objects.filter(scan=scan, finding__isnull=False):
        assert evidence.finding_id is not None
        assert evidence.sha256
        assert evidence.metadata['semantic_projection'] is True
        assert evidence.metadata['capability_id'] == 'browser.dom-snapshot'
