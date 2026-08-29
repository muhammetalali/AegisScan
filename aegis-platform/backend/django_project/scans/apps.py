from django.apps import AppConfig


class ScansConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.scans'
    label = 'scans'
    verbose_name = 'Scans'

    def ready(self):
        from django_project.scans import signals  # noqa: F401
