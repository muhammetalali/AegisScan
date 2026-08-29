from django.apps import AppConfig


class VulnerabilitiesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.vulnerabilities'
    label = 'vulnerabilities'
    verbose_name = 'Vulnerabilities'

    def ready(self):
        from django_project.vulnerabilities import signals  # noqa: F401
