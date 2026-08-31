from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0002_user_session_version"),
    ]

    operations = [
        migrations.RemoveIndex(
            model_name="loginattempt",
            name="users_login_email_9feded_idx",
        ),
        migrations.RemoveIndex(
            model_name="loginattempt",
            name="users_login_ip_addr_4650d9_idx",
        ),
    ]
