from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_project.users'
    label = 'users'
    verbose_name = 'Users & Authentication'

    def ready(self):
        from django_project.users import signals  # noqa: F401
