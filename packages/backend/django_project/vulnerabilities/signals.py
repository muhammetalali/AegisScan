from django.db import IntegrityError, transaction
from django.db.models import F
from django.db.models.signals import post_save
from django.dispatch import receiver

from .identity import build_canonical_identity
from .models import CanonicalFinding, Vulnerability


def _decrement_observation_count(canonical_id):
    if not canonical_id:
        return
    CanonicalFinding.objects.filter(
        pk=canonical_id,
        observation_count__gt=0,
    ).update(observation_count=F("observation_count") - 1)


@receiver(post_save, sender=Vulnerability)
def attach_canonical_finding(sender, instance: Vulnerability, created: bool, **kwargs) -> None:
    """Attach every persisted observation to its project-scoped canonical finding.

    The signal keeps canonical observation counts correct when an existing
    Vulnerability changes identity and therefore moves between canonical findings.
    """
    fingerprint, rule_key, normalized_target, canonical_title = build_canonical_identity(instance)
    previous_canonical_id = instance.canonical_finding_id

    try:
        with transaction.atomic():
            canonical, _ = CanonicalFinding.objects.get_or_create(
                project_id=instance.project_id,
                fingerprint=fingerprint,
                defaults={
                    "rule_key": rule_key,
                    "title": canonical_title,
                    "category": instance.category or "",
                    "normalized_target": normalized_target,
                    "source_engines": [instance.source_engine] if instance.source_engine else [],
                    "observation_count": 0,
                },
            )

            source_engines = list(canonical.source_engines or [])
            if instance.source_engine and instance.source_engine not in source_engines:
                source_engines.append(instance.source_engine)

            moved_between_canonicals = bool(
                previous_canonical_id and previous_canonical_id != canonical.pk
            )
            is_new_observation = created or not previous_canonical_id
            if moved_between_canonicals:
                _decrement_observation_count(previous_canonical_id)
                is_new_observation = True

            update_fields = {
                "rule_key": canonical.rule_key or rule_key,
                "title": canonical.title or canonical_title,
                "category": canonical.category or instance.category or "",
                "normalized_target": canonical.normalized_target or normalized_target,
                "source_engines": source_engines,
                "last_seen": instance.last_seen,
            }
            if is_new_observation:
                update_fields["observation_count"] = F("observation_count") + 1

            # Avoid saving the Vulnerability instance again; this signal must never recurse.
            CanonicalFinding.objects.filter(pk=canonical.pk).update(**update_fields)

            if is_new_observation or moved_between_canonicals:
                sender.objects.filter(pk=instance.pk).update(canonical_finding_id=canonical.pk)
                instance.canonical_finding_id = canonical.pk
    except IntegrityError:
        # A concurrent engine may have inserted the same canonical fingerprint.
        canonical = CanonicalFinding.objects.get(
            project_id=instance.project_id,
            fingerprint=fingerprint,
        )
        sender.objects.filter(pk=instance.pk).update(canonical_finding_id=canonical.pk)
        instance.canonical_finding_id = canonical.pk
