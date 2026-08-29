from django.apps import AppConfig


class KnowledgeConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.knowledge'
    label = 'knowledge'
    verbose_name = 'Knowledge Base'

    def ready(self):
        from django_project.knowledge import signals  # noqa: F401
