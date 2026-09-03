import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0006_authorization_decision_lifecycle'),
    ]

    operations = [
        migrations.AddField(
            model_name='assetauthorization',
            name='request_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
    ]
