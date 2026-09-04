from __future__ import annotations

from datetime import datetime, timezone

from django.db.models.signals import post_save
from django.dispatch import receiver

from django_project.scans.models import Scan, ScanEngineExecution
from django_project.vulnerabilities.models import Vulnerability

from .models import Evidence


@receiver(post_save, sender=Scan)
def reconcile_completed_nmap_scan(sender, instance: Scan, **kwargs) -> None:
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
