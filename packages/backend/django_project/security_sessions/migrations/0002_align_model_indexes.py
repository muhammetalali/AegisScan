from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("security_sessions", "0001_initial"),
    ]

    operations = [
        migrations.RenameIndex(
            model_name="evidencerecord",
            old_name="security_ev_session__b9dc4b_idx",
            new_name="security_se_session_1908d5_idx",
        ),
        migrations.RenameIndex(
            model_name="evidencerecord",
            old_name="security_ev_session__68cb9d_idx",
            new_name="security_se_session_dc7c9a_idx",
        ),
        migrations.RenameIndex(
            model_name="evidencerecord",
            old_name="security_ev_event_ha_91cb42_idx",
            new_name="security_se_event_h_24f9cd_idx",
        ),
        migrations.RenameIndex(
            model_name="executionidentity",
            old_name="security_ex_expires_00c3c5_idx",
            new_name="security_se_expires_1bf5df_idx",
        ),
        migrations.RenameIndex(
            model_name="executionidentity",
            old_name="security_ex_revoked_5c4252_idx",
            new_name="security_se_revoked_f5f050_idx",
        ),
        migrations.RenameIndex(
            model_name="securitytestsession",
            old_name="security_se_project_6f6af2_idx",
            new_name="security_se_project_ee7995_idx",
        ),
        migrations.RenameIndex(
            model_name="securitytestsession",
            old_name="security_se_expires_2c4b6c_idx",
            new_name="security_se_expires_f90400_idx",
        ),
        migrations.RenameIndex(
            model_name="securitytestsession",
            old_name="security_se_authoriz_6e5d79_idx",
            new_name="security_se_authori_4a4c8b_idx",
        ),
    ]
