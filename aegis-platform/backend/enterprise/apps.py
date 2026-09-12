from django.apps import AppConfig


class EnterpriseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise'

    def ready(self):
        from . import signals  # noqa: F401
