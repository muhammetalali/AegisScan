from django.apps import AppConfig


class EvidenceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.evidence'
    label = 'evidence'
    verbose_name = 'Evidence'

    def ready(self):
        from . import signals  # noqa: F401
