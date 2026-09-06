from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from django_project.scans.models import Scan

from .models import ContinuousAssuranceExecution


@receiver(post_save, sender=Scan, dispatch_uid='enterprise.finalize_continuous_assurance_execution')
def finalize_continuous_assurance_execution(sender, instance: Scan, **_kwargs):
    """Project a terminal scanner outcome onto its durable assurance occurrence."""
    if not instance.is_finished:
        return
    completed = instance.status in {Scan.Status.COMPLETED, Scan.Status.PARTIAL}
    ContinuousAssuranceExecution.objects.filter(
        scan_id=instance.id,
        status__in=[
            ContinuousAssuranceExecution.Status.PENDING,
            ContinuousAssuranceExecution.Status.RUNNING,
            ContinuousAssuranceExecution.Status.QUEUED,
        ],
    ).update(
        status=ContinuousAssuranceExecution.Status.COMPLETED if completed else ContinuousAssuranceExecution.Status.FAILED,
        reason=instance.error_message or '',
        completed_at=instance.completed_at or timezone.now(),
        updated_at=timezone.now(),
    )
