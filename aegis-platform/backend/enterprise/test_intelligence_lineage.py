from __future__ import annotations

import pytest
from asgiref.sync import async_to_sync

from django_project.assets.models import Asset
from django_project.intelligence.models import IntelligenceEnrichment
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.users.models import User
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.intelligence.fusion import FusionResult

from enterprise.models import FindingIntelligence
from enterprise.services import fuse_finding
from fastapi_app.routers.investigation import _workspace


@pytest.fixture
def finding(db):
    user = User.objects.create_user(email='lineage@example.invalid', password='Strong-Test-Password-123!')
    project = Project.objects.create(name='Intelligence lineage', slug='intelligence-lineage', owner=user)
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Affected service',
        slug='affected-service',
        type=Asset.Type.WEBSITE,
    )
    scan = Scan.objects.create(
        project=project,
        name='Lineage scan',
        scan_type=Scan.Type.URL,
        asset=asset,
        initiated_by=user,
    )
    item = Vulnerability.objects.create(
        project=project,
        scan=scan,
        asset=asset,
        title='CVE-backed finding',
        severity=Vulnerability.Severity.HIGH,
        cve_ids=['CVE-2021-44228'],
    )
    return user, item


class StubFusion:
    def __init__(self):
        self.calls = 0

    def enrich_cve(self, cve_id, *, nvd_api_key=None):
        self.calls += 1
        return FusionResult(
            cve_id=cve_id,
            sources={
                'nvd': {'generation': self.calls},
                'osv': {'id': cve_id},
                'cisa_kev': {'known_exploited': True, 'entry': {'cveID': cve_id}},
                'epss': {'data': [{'epss': '0.91'}]},
            },
            source_urls={'nvd': 'https://example.invalid/nvd'},
            provider_failures=[],
            confidence=95.0,
            conflicts=['provider summaries differ'],
            recommendation='Prioritize remediation.',
            explanation='Derived from the recorded providers.',
        )


@pytest.mark.django_db
def test_finding_analysis_has_immutable_snapshot_lineage(finding):
    user, vulnerability = finding
    fusion = StubFusion()

    first = fuse_finding(vulnerability, fusion=fusion, actor_id=str(user.id))
    first_snapshot_id = first.source_snapshot_id
    second = fuse_finding(vulnerability, fusion=fusion, actor_id=str(user.id))

    assert fusion.calls == 2
    assert first.pk == second.pk
    assert second.primary_cve == 'CVE-2021-44228'
    assert second.analysis_version == '1.0'
    assert second.source_snapshot_id != first_snapshot_id
    assert second.nvd == second.source_snapshot.sources['nvd']
    assert second.cisa_kev == second.source_snapshot.sources['cisa_kev']
    assert second.confidence == second.source_snapshot.confidence
    assert second.conflict is True
    assert IntelligenceEnrichment.objects.filter(cve_id='CVE-2021-44228').count() == 2
    assert IntelligenceEnrichment.objects.get(pk=first_snapshot_id).sources['nvd']['generation'] == 1

    workspace = async_to_sync(_workspace)(
        str(vulnerability.project_id),
        str(user.id),
        str(vulnerability.id),
        10,
    )
    assert len(workspace.intelligence) == 1
    assert workspace.intelligence[0].id == str(second.source_snapshot_id)
    assert workspace.intelligence[0].finding_id == str(vulnerability.id)
    assert workspace.intelligence[0].analysis_version == '1.0'


@pytest.mark.django_db
def test_finding_analysis_rejects_missing_cve(finding):
    _, vulnerability = finding
    vulnerability.cve_ids = []
    vulnerability.save(update_fields=['cve_ids'])

    with pytest.raises(ValueError, match='requires at least one CVE'):
        fuse_finding(vulnerability, fusion=StubFusion())

    assert not FindingIntelligence.objects.filter(vulnerability=vulnerability).exists()
