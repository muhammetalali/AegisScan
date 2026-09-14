from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence, FindingConfirmation
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.nmap_finding_ingestion import ingest_nmap_findings
from fastapi_app.services.wstg_observation_lineage import attach_wstg_evidence_metadata


@pytest.mark.django_db
def test_nmap_observation_persists_wstg_lineage_without_governance_side_effects():
    User = get_user_model()
    user = User.objects.create_user(
        email='wstg-lineage-persistence@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Lineage Persistence',
        slug='wstg-lineage-persistence',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='WSTG Nmap Target',
        slug='wstg-nmap-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'ip': '127.0.0.1'},
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='WSTG Nmap Lineage',
        scan_type=Scan.Type.IP,
        engines=['nmap'],
        initiated_by=user,
    )

    evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='<nmaprun/>',
        metadata=attach_wstg_evidence_metadata(
            {
                'target': '127.0.0.1',
                'exit_code': 0,
                'authorization_decision_id': 'reality-authorization-ref',
            },
            'network.nmap',
        ),
        collected_by=user,
    )
    parsed = {
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
        'host_count': 1,
        'open_ports': 1,
    }

    findings = ingest_nmap_findings(scan, evidence, parsed)
    assert len(findings) == 1

    finding = Vulnerability.objects.get(pk=findings[0].id)
    finding_lineage = finding.raw_data['_aegisscan_wstg']
    assert finding.status == Vulnerability.Status.OPEN
    assert finding.validation_status == 'unverified'
    assert finding_lineage['capability_id'] == 'network.nmap'
    assert finding_lineage['claim_policy'] == 'observation-only'
    assert finding_lineage['completion_claim_allowed'] is False
    assert len(finding_lineage['lineage_fingerprint']) == 64
    assert {item['wstg_id'] for item in finding_lineage['tests']} == {
        'WSTG-v42-INFO-02',
        'WSTG-v42-INFO-04',
        'WSTG-v42-INFO-10',
        'WSTG-v42-CONF-01',
        'WSTG-v42-CONF-05',
    }

    linked = Evidence.objects.get(pk=evidence.id)
    assert linked.finding_id == finding.id
    evidence_lineage = linked.metadata['wstg_lineage']
    assert evidence_lineage['lineage_fingerprint'] == finding_lineage['lineage_fingerprint']
    assert evidence_lineage['completion_claim_allowed'] is False
    assert all(item['completion_claim_allowed'] is False for item in evidence_lineage['tests'])

    assert FindingConfirmation.objects.filter(finding=finding).count() == 0
    assert finding.confirmation_records.count() == 0


@pytest.mark.django_db
def test_reingestion_refreshes_trusted_lineage_without_reopening_governed_state():
    User = get_user_model()
    user = User.objects.create_user(
        email='wstg-lineage-redelivery@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(
        name='WSTG Lineage Redelivery',
        slug='wstg-lineage-redelivery',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='WSTG Redelivery Target',
        slug='wstg-redelivery-target',
        type=Asset.Type.IP_ADDRESS,
        configuration={'ip': '127.0.0.1'},
    )
    scan = Scan.objects.create(
        project=project,
        asset=asset,
        name='WSTG Nmap Redelivery',
        scan_type=Scan.Type.IP,
        engines=['nmap'],
        initiated_by=user,
    )
    parsed = {
        'hosts': [{
            'ip': '127.0.0.1',
            'ports': [{
                'port': 8443,
                'protocol': 'tcp',
                'state': 'open',
                'service': 'https-alt',
                'product': 'fixture',
                'version': '1',
            }],
        }],
    }

    first_evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='<first/>',
        metadata=attach_wstg_evidence_metadata({'target': '127.0.0.1'}, 'network.nmap'),
        collected_by=user,
    )
    first = ingest_nmap_findings(scan, first_evidence, parsed)[0]
    first.status = Vulnerability.Status.ACCEPTED_RISK
    first.raw_data['_aegisscan_wstg'] = {'attacker_controlled': True}
    first.save(update_fields=['status', 'raw_data', 'updated_at'])

    second_evidence = Evidence.objects.create(
        scan=scan,
        asset=asset,
        source='nmap',
        evidence_type='scanner_output',
        raw_output='<second/>',
        metadata=attach_wstg_evidence_metadata({'target': '127.0.0.1'}, 'network.nmap'),
        collected_by=user,
    )
    second = ingest_nmap_findings(scan, second_evidence, parsed)[0]
    second.refresh_from_db()

    assert second.id == first.id
    assert second.status == Vulnerability.Status.ACCEPTED_RISK
    assert 'attacker_controlled' not in second.raw_data['_aegisscan_wstg']
    assert second.raw_data['_aegisscan_wstg']['completion_claim_allowed'] is False
    assert FindingConfirmation.objects.filter(finding=second).count() == 0
