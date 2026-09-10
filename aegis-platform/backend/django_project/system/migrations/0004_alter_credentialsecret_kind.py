from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('system', '0003_credential_vault'),
    ]

    operations = [
        migrations.AlterField(
            model_name='credentialsecret',
            name='kind',
            field=models.CharField(
                choices=[
                    ('password', 'Password'),
                    ('api_key', 'API Key'),
                    ('token', 'Token'),
                    ('ssh_private_key', 'SSH Private Key'),
                    ('cloud_access_key', 'Cloud Access Key'),
                    ('kubeconfig', 'Kubeconfig'),
                    ('generic', 'Generic Secret'),
                ],
                default='generic',
                max_length=30,
                verbose_name='kind',
            ),
        ),
    ]
