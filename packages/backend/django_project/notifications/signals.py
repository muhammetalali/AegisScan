from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from notifications.models import Notification


def _create_once(*, user, project, event_type: str, title: str, message: str, priority: str, resource_type: str, resource_id: str, action_url: str, data: dict) -> None:
    if user is None:
        return
    if Notification.objects.filter(
        user=user,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
    ).exists():
        return
    Notification.objects.create(
        user=user,
        project=project,
        event_type=event_type,
        title=title,
        message=message,
        priority=priority,
        status=Notification.Status.SENT,
        channels=["in_app"],
        sent_at=timezone.now(),
        resource_type=resource_type,
        resource_id=resource_id,
        action_url=action_url,
        data=data,
    )


@receiver(post_save, sender="scans.Scan")
def scan_notification(sender, instance, created: bool, **kwargs):
    user = instance.initiated_by
    project = instance.project
    scan_id = str(instance.pk)
    status = instance.status
    config = instance.config if isinstance(instance.config, dict) else {}
    target = str(config.get("target_value") or instance.name)

    if created or status == sender.Status.RUNNING:
        _create_once(
            user=user,
            project=project,
            event_type="scan_started",
            title="Scan started",
            message=f"Scan {instance.name} is running against {target}.",
            priority=Notification.Priority.NORMAL,
            resource_type="scan",
            resource_id=scan_id,
            action_url=f"/scan/{scan_id}/progress",
            data={"status": status, "target": target},
        )
    elif status == sender.Status.COMPLETED:
        _create_once(
            user=user,
            project=project,
            event_type="scan_completed",
            title="Scan completed",
            message=f"Scan {instance.name} completed with {instance.findings_count} findings.",
            priority=Notification.Priority.NORMAL,
            resource_type="scan",
            resource_id=scan_id,
            action_url=f"/scan/{scan_id}/results",
            data={"status": status, "target": target, "findings_count": instance.findings_count},
        )
    elif status == sender.Status.FAILED:
        _create_once(
            user=user,
            project=project,
            event_type="scan_failed",
            title="Scan failed",
            message=f"Scan {instance.name} failed: {instance.error_message or 'execution failed'}.",
            priority=Notification.Priority.HIGH,
            resource_type="scan",
            resource_id=scan_id,
            action_url=f"/scan/{scan_id}/progress",
            data={"status": status, "target": target, "error": instance.error_message},
        )
    elif status == sender.Status.CANCELLED:
        _create_once(
            user=user,
            project=project,
            event_type="scan_cancelled",
            title="Scan cancelled",
            message=f"Scan {instance.name} was cancelled.",
            priority=Notification.Priority.NORMAL,
            resource_type="scan",
            resource_id=scan_id,
            action_url=f"/scan/{scan_id}/progress",
            data={"status": status, "target": target},
        )


@receiver(post_save, sender="vulnerabilities.Vulnerability")
def vulnerability_notification(sender, instance, created: bool, **kwargs):
    if not created or instance.severity not in {sender.Severity.CRITICAL, sender.Severity.HIGH}:
        return
    event_type = "vuln_critical_found" if instance.severity == sender.Severity.CRITICAL else "vuln_high_found"
    priority = Notification.Priority.URGENT if instance.severity == sender.Severity.CRITICAL else Notification.Priority.HIGH
    _create_once(
        user=instance.scan.initiated_by if instance.scan else None,
        project=instance.project,
        event_type=event_type,
        title=f"{instance.get_severity_display()} vulnerability found",
        message=instance.title,
        priority=priority,
        resource_type="vulnerability",
        resource_id=str(instance.pk),
        action_url=f"/vulnerabilities/{instance.pk}",
        data={
            "severity": instance.severity,
            "title": instance.title,
            "asset_id": str(instance.asset_id) if instance.asset_id else None,
            "scan_id": str(instance.scan_id),
        },
    )
