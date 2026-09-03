from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('audit', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(
                choices=[
                    ('login', 'Login'), ('logout', 'Logout'), ('login_failed', 'Login Failed'),
                    ('password_change', 'Password Change'), ('password_reset', 'Password Reset'),
                    ('2fa_enable', '2FA Enabled'), ('2fa_disable', '2FA Disabled'),
                    ('api_request', 'API Request'), ('user_create', 'User Created'),
                    ('user_update', 'User Updated'), ('user_delete', 'User Deleted'),
                    ('user_role_change', 'User Role Changed'), ('user_permission_change', 'User Permission Changed'),
                    ('project_create', 'Project Created'), ('project_update', 'Project Updated'),
                    ('project_delete', 'Project Deleted'), ('project_archive', 'Project Archived'),
                    ('project_clone', 'Project Cloned'), ('project_member_add', 'Project Member Added'),
                    ('project_member_remove', 'Project Member Removed'), ('project_member_role_change', 'Project Member Role Changed'),
                    ('asset_create', 'Asset Created'), ('asset_update', 'Asset Updated'), ('asset_delete', 'Asset Deleted'),
                    ('scan_start', 'Scan Started'), ('scan_complete', 'Scan Completed'), ('scan_cancel', 'Scan Cancelled'),
                    ('scan_restart', 'Scan Restarted'), ('scan_schedule', 'Scan Scheduled'),
                    ('vuln_create', 'Vulnerability Created'), ('vuln_update', 'Vulnerability Updated'),
                    ('vuln_status_change', 'Vulnerability Status Changed'), ('vuln_assign', 'Vulnerability Assigned'),
                    ('vuln_note_add', 'Note Added to Vulnerability'), ('vuln_fix_verify', 'Vulnerability Fix Verified'),
                    ('report_generate', 'Report Generated'), ('report_download', 'Report Downloaded'),
                    ('report_share', 'Report Shared'), ('report_delete', 'Report Deleted'),
                    ('compliance_assess', 'Compliance Assessed'), ('compliance_report', 'Compliance Report Generated'),
                    ('knowledge_create', 'Knowledge Article Created'), ('knowledge_update', 'Knowledge Article Updated'),
                    ('knowledge_publish', 'Knowledge Article Published'), ('settings_change', 'Settings Changed'),
                    ('backup_create', 'Backup Created'), ('backup_restore', 'Backup Restored'),
                    ('api_key_create', 'API Key Created'), ('api_key_revoke', 'API Key Revoked'),
                ],
                max_length=50,
                verbose_name='action',
            ),
        ),
    ]
