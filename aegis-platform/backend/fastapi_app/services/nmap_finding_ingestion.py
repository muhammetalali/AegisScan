from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.evidence_identity import evidence_id
from fastapi_app.services.wstg_observation_lineage import attach_wstg_evidence_metadata, attach_wstg_finding_lineage


def ingest_nmap_findings(scan: Scan, evidence: Evidence, parsed: dict[str, Any]) -> list[Vulnerability]:
    """Persist real Nmap observations as scan-scoped findings without duplicate evidence on retry."""
    findings: list[Vulnerability] = []
    now = datetime.now(timezone.utc)
    primary_evidence_used = False
    duplicate_input_evidence = False

    for host in parsed.get('hosts', []):
        if not isinstance(host, dict):
            continue
        ip = str(host.get('ip') or '').strip()
        for port in host.get('ports', []):
            if not isinstance(port, dict) or str(port.get('state') or '').lower() != 'open':
                continue
            try:
                port_number = int(port.get('port'))
            except (TypeError, ValueError):
                continue
            if not 1 <= port_number <= 65535:
                continue

            protocol = str(port.get('protocol') or 'tcp').strip().lower()
            service = str(port.get('service') or '').strip().lower()
            product = str(port.get('product') or '').strip()
            version = str(port.get('version') or '').strip()
            service_label = service or 'unknown'
            product_label = product or service_label
            title = f'Exposed {protocol.upper()} port {port_number} ({service_label} / {product_label})'
            description = (
                f'Nmap detected an open {protocol.upper()} port {port_number} on '
                f'{ip or scan.asset.name}. Service={service_label}, '
                f'product={product_label}, version={version or "unknown"}.'
            )
            raw_data = attach_wstg_finding_lineage({'ip': ip, 'port': port_number, 'state': 'open', 'product': product, 'service': service, 'version': version, 'protocol': protocol}, 'network.nmap')

            vulnerability = Vulnerability.objects.filter(
                scan=scan, asset=scan.asset, source_engine='nmap',
                raw_data__port=port_number, raw_data__protocol=protocol,
            ).first()
            if vulnerability is None:
                vulnerability = Vulnerability.objects.create(
                    scan=scan, project=scan.project, asset=scan.asset,
                    title=title, description=description,
                    severity=Vulnerability.Severity.INFO, status=Vulnerability.Status.OPEN,
                    confidence=Vulnerability.Confidence.HIGH, category='network',
                    tags=['nmap', protocol] + ([service] if service else []),
                    risk_score=10.0, evidence_count=0, verified_evidence_count=0,
                    validation_status='unverified', source_engine='nmap', raw_data=raw_data,
                )
            else:
                vulnerability.title = title
                vulnerability.description = description
                vulnerability.raw_data = raw_data
                vulnerability.last_seen = now
                if vulnerability.status == Vulnerability.Status.FIXED:
                    vulnerability.status = Vulnerability.Status.OPEN
                    vulnerability.fixed_at = None
                    vulnerability.fixed_by = None
                vulnerability.save(update_fields=['title', 'description', 'raw_data', 'last_seen', 'status', 'fixed_at', 'fixed_by', 'updated_at'])

            existing = Evidence.objects.filter(
                scan=scan, asset=scan.asset, finding=vulnerability,
                source='nmap', evidence_type='scanner_output', sha256=evidence.sha256,
            ).exclude(pk=evidence.pk).first()
            if existing:
                duplicate_input_evidence = True
            elif not primary_evidence_used and evidence.finding_id in {None, vulnerability.id}:
                evidence.finding = vulnerability
                evidence.save(update_fields=['finding'])
                primary_evidence_used = True
            else:
                Evidence.objects.update_or_create(
                    id=evidence_id('scan', str(scan.id), 'nmap', 'scanner_output', str(vulnerability.id)),
                    defaults={
                        'scan': scan,
                        'asset': scan.asset,
                        'finding': vulnerability,
                        'source': 'nmap',
                        'evidence_type': 'scanner_output',
                        'raw_output': evidence.raw_output,
                        'metadata': attach_wstg_evidence_metadata({**(evidence.metadata or {}), 'observation_port': port_number, 'observation_protocol': protocol, 'observation_ip': ip, 'finding_id': str(vulnerability.id)}, 'network.nmap'),
                        'collected_by': evidence.collected_by,
                    },
                )

            vulnerability.evidence_count = vulnerability.evidence_records.count()
            vulnerability.save(update_fields=['evidence_count', 'updated_at'])
            findings.append(vulnerability)

    if duplicate_input_evidence and not primary_evidence_used:
        evidence.delete()
    return findings


def ingest_nmap_inventory(scan: Scan, parsed: dict[str, Any]) -> dict[str, int]:
    """Catalog observed hosts and open services from an already-authorized Nmap scan.

    Passive ingestion only: never dispatch new scans, mint authorization decisions,
    or authorize a discovered host outside the scan's immutable target snapshot.
    """
    import hashlib
    import ipaddress

    from django.db.models import Q
    from django_project.assets.models import Asset, AssetAuthorization, AssetRelationship, TechnologyFingerprint
    from fastapi_app.services.authorization_guard import asset_target
    from fastapi_app.services.asset_authorization_governance import initialize_asset_configuration

    counts = {'hosts_observed': 0, 'assets_created': 0, 'relationships_created': 0,
              'services_cataloged': 0}
    parent = scan.asset
    decision = scan.authorization_decision
    if (
        parent is None or not parent.is_active or
        parent.type not in {Asset.Type.IP_ADDRESS, Asset.Type.NETWORK_RANGE} or
        decision is None or not decision.authorized or not decision.is_currently_valid or
        decision.asset_id != parent.id or
        decision.target_snapshot != asset_target(parent) or
        not bool((parent.configuration or {}).get('authorized'))
    ):
        return counts
    current = AssetAuthorization.objects.filter(asset=parent).order_by('-created_at', '-id').first()
    if current is None or current.pk != decision.pk:
        return counts
    try:
        network = ipaddress.ip_network(decision.target_snapshot, strict=False)
    except ValueError:
        return counts

    # A single executor cannot unboundedly create DB rows from a large input.
    # The original scan evidence and parsed results are still retained in full.
    for host in parsed.get('hosts', [])[:1024]:
        if not isinstance(host, dict):
            continue
        try:
            address = ipaddress.ip_address(str(host.get('ip') or '').strip())
        except ValueError:
            continue
        if address not in network:
            continue
        ip = str(address)
        counts['hosts_observed'] += 1
        discovered = Asset.objects.filter(
            Q(configuration__ip=ip) | Q(configuration__host=ip),
            project=scan.project, type=Asset.Type.IP_ADDRESS,
        ).order_by('created_at').first()
        if discovered is None:
            slug = 'nmap-host-' + hashlib.sha256(address.packed).hexdigest()[:24]
            discovered, created = Asset.objects.get_or_create(
                project=scan.project, slug=slug,
                defaults={
                    'owner': scan.initiated_by, 'name': 'Discovered host ' + ip,
                    'type': Asset.Type.IP_ADDRESS,
                    'environment': parent.environment,
                    'criticality': parent.criticality,
                    'configuration': initialize_asset_configuration({'ip': ip}),
                    'tags': ['nmap-discovered'],
                    'metadata': {'discovered_from_scan_id': str(scan.id)},
                },
            )
            # Never attach a collision with a different target to this discovery.
            if discovered.type != Asset.Type.IP_ADDRESS or (discovered.configuration or {}).get('ip') != ip:
                continue
            if created:
                counts['assets_created'] += 1
        if discovered.id != parent.id:
            _relationship, created = AssetRelationship.objects.get_or_create(
                project=scan.project, source=parent, target=discovered,
                relationship_type=AssetRelationship.RelationshipType.CONTAINS
                if parent.type == Asset.Type.NETWORK_RANGE
                else AssetRelationship.RelationshipType.CONNECTS_TO,
            )
            if created:
                counts['relationships_created'] += 1

        for port in host.get('ports', [])[:128]:
            if not isinstance(port, dict) or str(port.get('state') or '').lower() != 'open':
                continue
            try:
                number = int(port.get('port'))
            except (ValueError, TypeError):
                continue
            if not 1 <= number <= 65535:
                continue
            protocol = str(port.get('protocol') or 'tcp').lower()
            if protocol not in {'tcp', 'udp'}:
                continue
            name = (str(port.get('product') or port.get('service') or 'unknown') + f' {protocol}/{number}')[:100]
            version = str(port.get('version') or '')[:50]
            evidence_ref = f'scan:{scan.id}:host:{ip}:{protocol}/{number}'
            _, created = TechnologyFingerprint.objects.get_or_create(
                asset=discovered, name=name, source='nmap', evidence=evidence_ref,
                defaults={
                    'version': version, 'category': 'network_service',
                    'confidence': 0.9 if port.get('product') else 0.7,
                },
            )
            if created:
                counts['services_cataloged'] += 1
    return counts
