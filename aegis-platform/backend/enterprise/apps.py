from django.apps import AppConfig


class EnterpriseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise'

    def import_models(self):
        super().import_models()
        from . import detection_models  # noqa: F401

    def ready(self):
        from . import signals  # noqa: F401
