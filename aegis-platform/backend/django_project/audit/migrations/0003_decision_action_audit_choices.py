from django.db import migrations, models
from django.utils.translation import gettext_lazy as _


class Migration(migrations.Migration):
    dependencies = [
        ('audit', '0002_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(
                choices=[
                    ('login', _('Login')), ('logout', _('Logout')), ('login_failed', _('Login Failed')),
                    ('password_change', _('Password Change')), ('password_reset', _('Password Reset')),
                    ('2fa_enable', _('2FA Enabled')), ('2fa_disable', _('2FA Disabled')),
                    ('user_create', _('User Created')), ('user_update', _('User Updated')), ('user_delete', _('User Deleted')),
                    ('user_role_change', _('User Role Changed')), ('user_permission_change', _('User Permission Changed')),
                    ('project_create', _('Project Created')), ('project_update', _('Project Updated')), ('project_delete', _('Project Deleted')),
                    ('project_archive', _('Project Archived')), ('project_clone', _('Project Cloned')),
                    ('project_member_add', _('Project Member Added')), ('project_member_remove', _('Project Member Removed')),
                    ('project_member_role_change', _('Project Member Role Changed')),
                    ('asset_create', _('Asset Created')), ('asset_update', _('Asset Updated')), ('asset_delete', _('Asset Deleted')),
                    ('scan_start', _('Scan Started')), ('scan_complete', _('Scan Completed')), ('scan_cancel', _('Scan Cancelled')),
                    ('scan_restart', _('Scan Restarted')), ('scan_schedule', _('Scan Scheduled')),
                    ('vuln_create', _('Vulnerability Created')), ('vuln_update', _('Vulnerability Updated')),
                    ('vuln_status_change', _('Vulnerability Status Changed')), ('vuln_assign', _('Vulnerability Assigned')),
                    ('vuln_note_add', _('Note Added to Vulnerability')), ('vuln_fix_verify', _('Vulnerability Fix Verified')),
                    ('decision_action_create', _('Decision Action Created')),
                    ('decision_action_transition', _('Decision Action Transitioned')),
                    ('report_generate', _('Report Generated')), ('report_download', _('Report Downloaded')),
                    ('report_share', _('Report Shared')), ('report_delete', _('Report Deleted')),
                    ('compliance_assess', _('Compliance Assessed')), ('compliance_report', _('Compliance Report Generated')),
                    ('knowledge_create', _('Knowledge Article Created')), ('knowledge_update', _('Knowledge Article Updated')),
                    ('knowledge_publish', _('Knowledge Article Published')), ('settings_change', _('Settings Changed')),
                    ('backup_create', _('Backup Created')), ('backup_restore', _('Backup Restored')),
                    ('api_key_create', _('API Key Created')), ('api_key_revoke', _('API Key Revoked')),
                ],
                max_length=50,
                verbose_name='action',
            ),
        ),
    ]
