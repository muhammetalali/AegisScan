
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('enterprise', '0020_http_protocol_security_validation_kind')]

    operations = [
        migrations.AlterField(
            model_name='websecurityvalidationrun',
            name='kind',
            field=models.CharField(
                max_length=40,
                choices=[
                    ('authorization_matrix', 'Authorization Matrix'),
                    ('negative_path', 'Negative Path'),
                    ('response_comparison', 'Response Comparison'),
                    ('websocket_security', 'WebSocket Security'),
                    ('graphql_security', 'GraphQL Security'),
                    ('cross_protocol', 'Cross-Protocol State'),
                    ('identity_protocol_security', 'Identity Protocol Security'),
                    ('http_protocol_security', 'HTTP Protocol Security'),
                    ('cache_origin_security', 'Cache Origin Security'),
                ],
            ),
        ),
    ]
