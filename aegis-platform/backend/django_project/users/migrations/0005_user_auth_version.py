from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('users', '0004_company_access_scopes')]

    operations = [
        migrations.AddField(
            model_name='user',
            name='auth_version',
            field=models.PositiveBigIntegerField(default=1),
        ),
    ]
