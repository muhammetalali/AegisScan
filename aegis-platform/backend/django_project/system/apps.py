from django.apps import AppConfig


class SystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.system'
    label = 'system'
    verbose_name = 'System Management'

    def ready(self):
        from django_project.system import signals  # noqa: F401
