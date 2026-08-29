from django.apps import AppConfig


class ComplianceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.compliance'
    label = 'compliance'
    verbose_name = 'Compliance'

    def ready(self):
        from django_project.compliance import signals  # noqa: F401
