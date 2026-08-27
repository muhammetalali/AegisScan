from django.apps import AppConfig

class ScansConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scans'
    verbose_name = 'Scans'

    def ready(self):
        import scans.signals  # noqa