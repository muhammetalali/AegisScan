from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from django_project.scans.models import Scan, ScanEngineExecution
from django_project.vulnerabilities.models import Vulnerability

from .models import Evidence


def _text(value: Any) -> str:
    return str(value or '').strip()


def _open_ports(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for host in parsed.get('hosts', []):
        if not isinstance(host, dict):
            continue
        host_ip = _text(host.get('ip'))
        for port in host.get('ports', []):
            if not isinstance(port, dict) or _text(port.get('state')).lower() != 'open':
                continue
            try:
                port_number = int(port.get('port'))
            except (TypeError, ValueError):
                continue
            if not 1 <= port_number <= 65535:
                continue
            result.append({
                'ip': host_ip,
                'port': port_number,
                'protocol': _text(port.get('protocol')).lower() or 'tcp',
                'state': 'open',
                'service': _text(port.get('service')).lower(),
                'product': _text(port.get('product')).lower(),
                'version': _text(port.get('version')).lower(),
            })
    return result


def _title(item: dict[str, Any]) -> str:
    service = item['service'] or 'unknown-service'
    product = item['product'] or ''
    suffix = f' / {product}' if product else ''
    return f"Exposed {item['protocol'].upper()} port {item['port']} ({service}{suffix})"


@receiver(post_save, sender=Evidence)
def ingest_nmap_scanner_evidence(sender, instance: Evidence, created: bool, **kwargs: Any) -> None:
    if not created or instance.source != 'nmap' or instance.evidence_type != 'scanner_output':
        return
    if not instance.scan or not instance.asset:
        return

    metadata = instance.metadata if isinstance(instance.metadata, dict) else {}
    if metadata.get('derived_from_evidence_id'):
        return
    parsed = metadata.get('parsed') if isinstance(metadata.get('parsed'), dict) else {}
    open_ports = _open_ports(parsed)
    now = datetime.now(timezone.utc)

    for item in open_ports:
        title = _title(item)
        signature = {
            'port': item['port'],
            'protocol': item['protocol'],
            'state': item['state'],
            'service': item['service'],
            'product': item['product'],
            'version': item['version'],
            'ip': item['ip'],
        }
        vulnerability = Vulnerability.objects.filter(
            asset=instance.asset,
            source_engine='nmap',
            title=title,
        ).order_by('-updated_at').first()

        if vulnerability:
            vulnerability.scan = instance.scan
            vulnerability.project = instance.scan.project
            vulnerability.last_seen = now
            vulnerability.raw_data = {**(vulnerability.raw_data if isinstance(vulnerability.raw_data, dict) else {}), **signature}
            vulnerability.validation_status = 'unverified'
            vulnerability.save(update_fields=['scan', 'project', 'last_seen', 'raw_data', 'validation_status', 'updated_at'])
        else:
            vulnerability = Vulnerability.objects.create(
                scan=instance.scan,
                project=instance.scan.project,
                asset=instance.asset,
                title=title,
                description='Nmap observed an open network service on the authorized asset.',
                severity=Vulnerability.Severity.INFO,
                status=Vulnerability.Status.OPEN,
                confidence=Vulnerability.Confidence.HIGH,
                category='network',
                tags=['nmap', 'exposed-port', item['protocol']] + ([item['service']] if item['service'] else []),
                url='',
                method='NMAP',
                risk_score=10.0,
                evidence_count=0,
                verified_evidence_count=0,
                validation_status='unverified',
                remediation='Restrict or close the service when it is not required; otherwise document the approved exposure and harden the service.',
                source_engine='nmap',
                raw_data=signature,
                first_seen=now,
                last_seen=now,
            )

        Evidence.objects.create(
            scan=instance.scan,
            asset=instance.asset,
            finding=vulnerability,
            source='nmap',
            evidence_type='scanner_output',
            raw_output=instance.raw_output,
            metadata={
                'format': 'xml',
                'target': metadata.get('target', ''),
                'exit_code': metadata.get('exit_code', 0),
                'derived_from_evidence_id': str(instance.id),
                'finding_signature': signature,
            },
            collected_by=instance.collected_by,
        )
        vulnerability.evidence_count = vulnerability.evidence_records.count()
        vulnerability.save(update_fields=['evidence_count', 'updated_at'])


@receiver(post_save, sender=Scan)
def reconcile_completed_nmap_scan(sender, instance: Scan, **kwargs: Any) -> None:
    if instance.status != Scan.Status.COMPLETED or (instance.current_engine or '').strip().lower() != 'nmap':
        return
    findings_count = Vulnerability.objects.filter(scan=instance).count()
    if instance.findings_count != findings_count:
        Scan.objects.filter(pk=instance.pk).update(findings_count=findings_count)
    execution = ScanEngineExecution.objects.filter(
        scan=instance,
        engine__name='nmap',
    ).order_by('-created_at').first()
    if execution:
        derived_evidence_count = Evidence.objects.filter(
            scan=instance,
            source='nmap',
            evidence_type='scanner_output',
            metadata__derived_from_evidence_id__isnull=False,
        ).count()
        desired_evidences = 1 + derived_evidence_count
        if execution.findings_found != findings_count or execution.evidences_collected != desired_evidences:
            ScanEngineExecution.objects.filter(pk=execution.pk).update(
                findings_found=findings_count,
                evidences_collected=desired_evidences,
            )
