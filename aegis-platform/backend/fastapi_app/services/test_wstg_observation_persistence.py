from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset, AssetAuthorization, AssetRelationship, TechnologyFingerprint
from django_project.evidence.models import Evidence, FindingConfirmation
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.nmap_finding_ingestion import ingest_nmap_findings, ingest_nmap_inventory
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


@pytest.mark.django_db
def test_nmap_passive_discovery_catalogs_only_hosts_within_approved_parent_network():
    User = get_user_model()
    operator = User.objects.create_user(
        email='nmap-inventory-operator@example.invalid', password='Strong-Test-Password-123!',
    )
    project = Project.objects.create(name='Approved Lab Network', slug='approved-lab-network', owner=operator)
    network = Asset.objects.create(
        project=project, owner=operator, name='Lab CIDR', slug='lab-cidr',
        type=Asset.Type.NETWORK_RANGE,
        configuration={'cidr': '192.0.2.0/29', 'authorized': True},
    )
    decision = AssetAuthorization.objects.create(
        asset=network, actor=operator, authorized=True,
        target_snapshot='192.0.2.0/29', reason='Approved lab CIDR baseline',
    )
    scan = Scan.objects.create(
        project=project, asset=network, name='Nmap existing authorized lab scan',
        scan_type=Scan.Type.NETWORK, initiated_by=operator,
        authorization_decision=decision, engines=['nmap'],
    )
    hosts = {
        'hosts': [
            {'ip': '192.0.2.2', 'ports': [
                {'port': 443, 'protocol': 'tcp', 'state': 'open',
                 'service': 'https', 'product': 'nginx', 'version': '1.2'},
                {'port': 22, 'protocol': 'tcp', 'state': 'closed', 'service': 'ssh'},
            ]},
            {'ip': '192.0.2.3', 'ports': [{'port': 53, 'protocol': 'udp',
                                         'state': 'open', 'service': 'domain'}]},
            {'ip': '198.51.100.9', 'ports': [{'port': 80, 'protocol': 'tcp',
                                             'state': 'open', 'service': 'http'}]},
            {'ip': 'invalid.example', 'ports': [{'port': 443, 'state': 'open'}]},
        ],
    }
    first = ingest_nmap_inventory(scan, hosts)
    assert first == {
        'hosts_observed': 2, 'assets_created': 2,
        'relationships_created': 2, 'services_cataloged': 2,
    }
    assert Asset.objects.filter(project=project, type=Asset.Type.IP_ADDRESS).count() == 2
    assert Asset.objects.filter(project=project, configuration__ip='198.51.100.9').count() == 0
    hosts_found = list(Asset.objects.filter(project=project, type=Asset.Type.IP_ADDRESS))
    assert {x.configuration['ip'] for x in hosts_found} == {'192.0.2.2', '192.0.2.3'}
    assert all(x.configuration['authorized'] is False for x in hosts_found)
    assert AssetAuthorization.objects.filter(asset__in=hosts_found).count() == 0
    assert AssetRelationship.objects.filter(
        project=project, source=network, relationship_type='contains',
    ).count() == 2
    assert TechnologyFingerprint.objects.filter(
        asset__in=hosts_found, source='nmap', category='network_service',
    ).count() == 2

    repeated = ingest_nmap_inventory(scan, hosts)
    assert repeated['assets_created'] == 0
    assert repeated['relationships_created'] == 0
    assert repeated['services_cataloged'] == 0
    assert Asset.objects.filter(project=project, type=Asset.Type.IP_ADDRESS).count() == 2

    AssetAuthorization.objects.create(
        asset=network, actor=operator, authorized=False,
        target_snapshot='192.0.2.0/29', reason='Stop lab scan authorization',
        supersedes=decision,
    )
    blocked = ingest_nmap_inventory(scan, {
        'hosts': [{'ip': '192.0.2.4', 'ports': []}],
    })
    assert blocked['assets_created'] == 0
    assert not Asset.objects.filter(project=project, configuration__ip='192.0.2.4').exists()
