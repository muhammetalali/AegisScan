from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.audit'
    label = 'audit'
    verbose_name = 'Audit & Security'

    def ready(self):
        from django_project.audit import signals  # noqa: F401
