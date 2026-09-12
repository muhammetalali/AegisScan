from django.apps import AppConfig


class SystemConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.system'
    label = 'system'
    verbose_name = 'System Management'

    def import_models(self):
        super().import_models()
        from django_project.system import credential_models  # noqa: F401

    def ready(self):
        from django_project.system import signals  # noqa: F401
