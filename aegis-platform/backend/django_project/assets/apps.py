from django.apps import AppConfig


class AssetsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.assets'
    label = 'assets'
    verbose_name = 'Assets'

    def ready(self):
        from django_project.assets import signals  # noqa: F401
