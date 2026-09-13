from django.apps import AppConfig


class EnterpriseConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise'

    def import_models(self):
        super().import_models()
        from . import detection_models  # noqa: F401
        from . import soc_models  # noqa: F401
        from . import assurance_models  # noqa: F401
        from . import assurance_obligation_models  # noqa: F401
        from . import campaign_models  # noqa: F401

    def ready(self):
        from . import signals  # noqa: F401
