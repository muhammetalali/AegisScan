from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability


def ingest_nmap_findings(scan: Scan, evidence: Evidence, parsed: dict[str, Any]) -> list[Vulnerability]:
    """Persist each real Nmap open-port observation as a scan-scoped finding.

    The scanner-level evidence can be linked to one finding for simple scans;
    additional findings receive their own evidence records so evidence ownership
    is never overwritten by the last observation in a multi-port scan.
    """
    findings: list[Vulnerability] = []
    now = datetime.now(timezone.utc)
    primary_evidence_used = False

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
            raw_data = {
                'ip': ip,
                'port': port_number,
                'state': 'open',
                'product': product,
                'service': service,
                'version': version,
                'protocol': protocol,
            }

            vulnerability = Vulnerability.objects.filter(
                scan=scan,
                asset=scan.asset,
                source_engine='nmap',
                raw_data__port=port_number,
                raw_data__protocol=protocol,
            ).first()

            if vulnerability is None:
                vulnerability = Vulnerability.objects.create(
                    scan=scan,
                    project=scan.project,
                    asset=scan.asset,
                    title=title,
                    description=description,
                    severity=Vulnerability.Severity.INFO,
                    status=Vulnerability.Status.OPEN,
                    confidence=Vulnerability.Confidence.HIGH,
                    category='network',
                    tags=['nmap', protocol] + ([service] if service else []),
                    risk_score=10.0,
                    evidence_count=0,
                    verified_evidence_count=0,
                    validation_status='unverified',
                    source_engine='nmap',
                    raw_data=raw_data,
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

            if not primary_evidence_used and evidence.finding_id in {None, vulnerability.id}:
                evidence.finding = vulnerability
                evidence.save(update_fields=['finding'])
                primary_evidence_used = True
            else:
                Evidence.objects.get_or_create(
                    scan=scan,
                    asset=scan.asset,
                    finding=vulnerability,
                    source='nmap',
                    evidence_type='scanner_output',
                    defaults={
                        'raw_output': evidence.raw_output,
                        'metadata': {
                            **(evidence.metadata or {}),
                            'observation_port': port_number,
                            'observation_protocol': protocol,
                            'observation_ip': ip,
                            'finding_id': str(vulnerability.id),
                        },
                        'collected_by': evidence.collected_by,
                    },
                )

            vulnerability.evidence_count = vulnerability.evidence_records.count()
            vulnerability.save(update_fields=['evidence_count', 'updated_at'])
            findings.append(vulnerability)

    return findings
