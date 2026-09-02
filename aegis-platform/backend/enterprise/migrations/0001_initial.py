from django.db import migrations

class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ('compliance', '0002_initial'),
        ('projects', '0002_initial'),
        ('scans', '0002_initial'),
        ('vulnerabilities', '0001_initial'),
        migrations.swappable_dependency('users.User'),
    ]
    operations = []
