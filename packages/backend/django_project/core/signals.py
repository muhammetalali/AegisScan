"""Domain signals that turn persistence changes into dashboard events."""

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from core.events import publish_dashboard_event, publish_user_dashboard_event


def _emit(instance, reason):
    project_id = getattr(instance, "project_id", None)
    if project_id:
        publish_dashboard_event(
            project_id=project_id,
            reason=reason,
            entity=instance.__class__.__name__,
            entity_id=instance.pk,
        )


@receiver(post_save, sender="projects.Project")
def project_changed(sender, instance, created, **kwargs):
    _emit(instance, "project.created" if created else "project.updated")


@receiver(post_delete, sender="projects.Project")
def project_deleted(sender, instance, **kwargs):
    _emit(instance, "project.deleted")


@receiver(post_save, sender="projects.ProjectMembership")
def membership_changed(sender, instance, created, **kwargs):
    publish_user_dashboard_event(
        user_id=instance.user_id,
        project_id=instance.project_id,
        reason="membership.created" if created else "membership.updated",
        entity="ProjectMembership",
        entity_id=instance.pk,
    )
    # Existing members also need their aggregate counts refreshed.
    _emit(instance, "membership.changed")


@receiver(post_delete, sender="projects.ProjectMembership")
def membership_deleted(sender, instance, **kwargs):
    publish_user_dashboard_event(
        user_id=instance.user_id,
        project_id=instance.project_id,
        reason="membership.deleted",
        entity="ProjectMembership",
        entity_id=instance.pk,
    )
    _emit(instance, "membership.deleted")


@receiver(post_save, sender="scans.Scan")
def scan_changed(sender, instance, created, **kwargs):
    _emit(instance, "scan.created" if created else "scan.updated")


@receiver(post_delete, sender="scans.Scan")
def scan_deleted(sender, instance, **kwargs):
    _emit(instance, "scan.deleted")


@receiver(post_save, sender="vulnerabilities.Vulnerability")
def vulnerability_changed(sender, instance, created, **kwargs):
    _emit(instance, "vulnerability.created" if created else "vulnerability.updated")


@receiver(post_delete, sender="vulnerabilities.Vulnerability")
def vulnerability_deleted(sender, instance, **kwargs):
    _emit(instance, "vulnerability.deleted")


@receiver(post_save, sender="assets.Asset")
def asset_changed(sender, instance, created, **kwargs):
    _emit(instance, "asset.created" if created else "asset.updated")


@receiver(post_delete, sender="assets.Asset")
def asset_deleted(sender, instance, **kwargs):
    _emit(instance, "asset.deleted")
