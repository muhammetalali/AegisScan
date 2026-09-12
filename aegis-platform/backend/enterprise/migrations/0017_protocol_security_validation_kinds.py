from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0016_web_security_foundation'),
    ]

    operations = [
        migrations.AlterField(
            model_name='websecurityvalidationrun',
            name='kind',
            field=models.CharField(
                choices=[
                    ('authorization_matrix', 'Authorization Matrix'),
                    ('negative_path', 'Negative Path'),
                    ('response_comparison', 'Response Comparison'),
                    ('websocket_security', 'WebSocket Security'),
                    ('graphql_security', 'GraphQL Security'),
                    ('cross_protocol', 'Cross-Protocol State'),
                ],
                max_length=40,
            ),
        ),
    ]
