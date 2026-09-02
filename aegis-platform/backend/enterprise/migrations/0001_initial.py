from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid

class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ('compliance', '0002_initial'),
        ('projects', '0002_initial'),
        ('scans', '0002_initial'),
        ('vulnerabilities', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = []
