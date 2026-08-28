"""Domain signals that turn persistence changes into dashboard events."""

from django.db.models.signals import post_delete, post_save, pre_delete
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


@receiver(pre_delete, sender="projects.Project")
def project_before_delete(sender, instance, **kwargs):
    # M2M rows can be removed as part of the cascade before post_delete. Capture
    # recipients while the membership relation is still available.
    instance._dashboard_recipient_ids = set(instance.members.values_list("id", flat=True))
    if instance.owner_id:
        instance._dashboard_recipient_ids.add(instance.owner_id)


@receiver(post_delete, sender="projects.Project")
def project_deleted(sender, instance, **kwargs):
    for user_id in getattr(instance, "_dashboard_recipient_ids", set()):
        publish_user_dashboard_event(
            user_id=user_id,
            project_id=instance.pk,
            reason="project.deleted",
            entity="Project",
            entity_id=instance.pk,
        )


@receiver(post_save, sender="projects.ProjectMembership")
def membership_changed(sender, instance, created, **kwargs):
    publish_user_dashboard_event(
        user_id=instance.user_id,
        project_id=instance.project_id,
        reason="membership.created" if created else "membership.updated",
        entity="ProjectMembership",
        entity_id=instance.pk,
    )
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
