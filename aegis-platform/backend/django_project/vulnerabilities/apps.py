from django.apps import AppConfig

class VulnerabilitiesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vulnerabilities'
    verbose_name = 'Vulnerabilities'

    def ready(self):
        import vulnerabilities.signals  # noqa