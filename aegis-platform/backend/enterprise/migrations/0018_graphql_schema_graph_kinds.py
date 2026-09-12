from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('enterprise', '0017_protocol_security_validation_kinds'),
    ]

    operations = [
        migrations.AlterField(
            model_name='securitygraphnode',
            name='kind',
            field=models.CharField(
                choices=[
                    ('page', 'Page'),
                    ('endpoint', 'Endpoint'),
                    ('channel', 'Channel'),
                    ('graphql_operation', 'GraphQL Operation'),
                    ('graphql_type', 'GraphQL Type'),
                    ('graphql_field', 'GraphQL Field'),
                    ('graphql_argument', 'GraphQL Argument'),
                    ('websocket_channel', 'WebSocket Channel'),
                    ('identity', 'Identity'),
                    ('session', 'Session'),
                    ('role', 'Role'),
                    ('tenant', 'Tenant'),
                    ('resource', 'Resource'),
                    ('policy', 'Policy'),
                    ('observation', 'Observation'),
                    ('evidence', 'Evidence'),
                    ('finding', 'Finding'),
                    ('attack_chain', 'Attack Chain'),
                    ('detection', 'Detection'),
                    ('risk', 'Risk'),
                    ('control', 'Control'),
                    ('remediation', 'Remediation'),
                    ('revalidation', 'Revalidation'),
                    ('service', 'Service'),
                    ('cache', 'Cache'),
                    ('reverse_proxy', 'Reverse Proxy'),
                    ('database', 'Database'),
                    ('external_service', 'External Service'),
                    ('threat', 'Threat'),
                    ('ttp', 'ATT&CK TTP'),
                    ('asset', 'Asset'),
                    ('capability', 'Capability'),
                    ('trust_boundary', 'Trust Boundary'),
                    ('data_flow', 'Data Flow'),
                ],
                max_length=40,
            ),
        ),
    ]
