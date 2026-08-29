from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.RenameIndex(
            model_name='user',
            old_name='users_user_role_36d76_idx',
            new_name='users_user_role_36d76d_idx',
        ),
    ]
