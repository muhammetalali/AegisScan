from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("audit", "0004_align_model_state")]

    operations = [
        migrations.AlterField(model_name="dataexport", name="completed_at", field=models.DateTimeField(blank=True, null=True, verbose_name="completed at")),
        migrations.AlterField(model_name="dataexport", name="downloaded_at", field=models.DateTimeField(blank=True, null=True, verbose_name="downloaded at")),
        migrations.AlterField(model_name="dataexport", name="error_message", field=models.TextField(blank=True, verbose_name="error message")),
        migrations.AlterField(model_name="dataexport", name="expires_at", field=models.DateTimeField(verbose_name="expires at")),
        migrations.AlterField(model_name="dataexport", name="fields", field=models.JSONField(blank=True, default=list, verbose_name="fields")),
        migrations.AlterField(model_name="dataexport", name="file", field=models.FileField(blank=True, null=True, upload_to="exports/", verbose_name="file")),
        migrations.AlterField(model_name="dataexport", name="file_size", field=models.PositiveIntegerField(default=0, verbose_name="file size")),
        migrations.AlterField(model_name="dataexport", name="filters", field=models.JSONField(blank=True, default=dict, verbose_name="filters")),
        migrations.AlterField(model_name="dataexport", name="format", field=models.CharField(choices=[("csv", "CSV"), ("json", "JSON"), ("excel", "Excel"), ("pdf", "PDF")], max_length=10, verbose_name="format")),
        migrations.AlterField(model_name="dataexport", name="name", field=models.CharField(max_length=200, verbose_name="name")),
        migrations.AlterField(model_name="dataexport", name="record_count", field=models.PositiveIntegerField(default=0, verbose_name="record count")),
        migrations.AlterField(model_name="dataexport", name="resource_type", field=models.CharField(max_length=50, verbose_name="resource type")),
        migrations.AlterField(model_name="dataexport", name="status", field=models.CharField(choices=[("pending", "Pending"), ("processing", "Processing"), ("completed", "Completed"), ("failed", "Failed"), ("expired", "Expired")], default="pending", max_length=15, verbose_name="status")),
        migrations.AlterField(model_name="securityevent", name="description", field=models.TextField(verbose_name="description")),
        migrations.AlterField(model_name="securityevent", name="event_type", field=models.CharField(choices=[("brute_force", "Brute Force Attack"), ("suspicious_login", "Suspicious Login"), ("privilege_escalation", "Privilege Escalation"), ("data_exfiltration", "Data Exfiltration"), ("unauthorized_access", "Unauthorized Access"), ("config_change", "Configuration Change"), ("scan_anomaly", "Scan Anomaly"), ("vuln_spike", "Vulnerability Spike")], max_length=30, verbose_name="event type")),
        migrations.AlterField(model_name="securityevent", name="indicators", field=models.JSONField(default=list, verbose_name="indicators")),
        migrations.AlterField(model_name="securityevent", name="raw_data", field=models.JSONField(blank=True, default=dict, verbose_name="raw data")),
        migrations.AlterField(model_name="securityevent", name="resolution_notes", field=models.TextField(blank=True, verbose_name="resolution notes")),
        migrations.AlterField(model_name="securityevent", name="resolved_at", field=models.DateTimeField(blank=True, null=True, verbose_name="resolved at")),
        migrations.AlterField(model_name="securityevent", name="severity", field=models.CharField(choices=[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")], max_length=15, verbose_name="severity")),
        migrations.AlterField(model_name="securityevent", name="source_ip", field=models.GenericIPAddressField(blank=True, null=True, verbose_name="source IP")),
        migrations.AlterField(model_name="securityevent", name="status", field=models.CharField(choices=[("new", "New"), ("investigating", "Investigating"), ("resolved", "Resolved"), ("false_positive", "False Positive")], default="new", max_length=20, verbose_name="status")),
        migrations.AlterField(model_name="securityevent", name="target_resource_id", field=models.CharField(blank=True, max_length=100, verbose_name="target resource ID")),
        migrations.AlterField(model_name="securityevent", name="target_resource_type", field=models.CharField(blank=True, max_length=50, verbose_name="target resource type")),
        migrations.AlterField(model_name="securityevent", name="title", field=models.CharField(max_length=300, verbose_name="title")),
    ]
