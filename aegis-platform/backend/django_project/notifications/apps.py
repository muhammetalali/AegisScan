from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.notifications'
    label = 'notifications'
    verbose_name = 'Notifications'

    def ready(self):
        from django_project.notifications import signals  # noqa: F401
