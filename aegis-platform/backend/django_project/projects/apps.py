from django.apps import AppConfig


class ProjectsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.projects'
    label = 'projects'
    verbose_name = 'Projects'

    def ready(self):
        from django_project.projects import signals  # noqa: F401
