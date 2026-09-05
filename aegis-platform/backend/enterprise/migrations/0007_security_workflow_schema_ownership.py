from django.db import migrations


def create_security_workflow_schema(_apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    statements = [
        """CREATE TABLE IF NOT EXISTS security_decision_actions (
            action_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, node_id TEXT NOT NULL, title TEXT NOT NULL,
            owner TEXT NOT NULL, requested_by TEXT NOT NULL, sla_hours INTEGER NOT NULL CHECK (sla_hours > 0),
            state TEXT NOT NULL, risk_before INTEGER NOT NULL DEFAULT 0, confidence_before INTEGER NOT NULL DEFAULT 0,
            priority INTEGER NOT NULL DEFAULT 0, recommended_action TEXT NOT NULL,
            remediation_plan JSONB NOT NULL DEFAULT '[]'::jsonb, created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL, version INTEGER NOT NULL DEFAULT 1,
            sla_status TEXT NOT NULL DEFAULT 'on_track', escalation_level INTEGER NOT NULL DEFAULT 0
        )""",
        "ALTER TABLE security_decision_actions ADD COLUMN IF NOT EXISTS sla_status TEXT NOT NULL DEFAULT 'on_track'",
        "ALTER TABLE security_decision_actions ADD COLUMN IF NOT EXISTS escalation_level INTEGER NOT NULL DEFAULT 0",
        """CREATE TABLE IF NOT EXISTS security_decision_action_events (
            event_id BIGSERIAL PRIMARY KEY,
            action_id TEXT NOT NULL REFERENCES security_decision_actions(action_id) ON DELETE CASCADE,
            event_type TEXT NOT NULL, actor TEXT NOT NULL, note TEXT, created_at TIMESTAMPTZ NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_action_events_action_id_created ON security_decision_action_events(action_id, created_at)",
        "CREATE INDEX IF NOT EXISTS idx_actions_state_updated ON security_decision_actions(state, updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_actions_owner_sla ON security_decision_actions(owner, sla_status, created_at)",
        """CREATE TABLE IF NOT EXISTS assurance_policies (
            policy_id TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE, priority INTEGER NOT NULL DEFAULT 0,
            conditions JSONB NOT NULL DEFAULT '{}'::jsonb, actions JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (policy_id, version)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_assurance_policies_enabled_priority ON assurance_policies(enabled, priority DESC, version DESC)",
        """INSERT INTO assurance_policies
            (policy_id, version, name, enabled, priority, conditions, actions, created_by, created_at)
            VALUES
            ('critical-production',1,'Critical production risk',TRUE,100,'{"risk_gte":90,"environment":"production"}'::jsonb,'{"approval_role":"ciso","approval_count":2,"sla_hours":2,"escalate_after_minutes":60,"escalation_targets":["security_manager","ciso"]}'::jsonb,'system',NOW()),
            ('critical',1,'Critical risk',TRUE,90,'{"risk_gte":90}'::jsonb,'{"approval_role":"ciso","approval_count":1,"sla_hours":4,"escalate_after_minutes":120,"escalation_targets":["security_manager","ciso"]}'::jsonb,'system',NOW()),
            ('high',1,'High risk',TRUE,80,'{"risk_gte":75}'::jsonb,'{"approval_role":"security_manager","approval_count":1,"sla_hours":24,"escalate_after_minutes":360,"escalation_targets":["security_manager"]}'::jsonb,'system',NOW()),
            ('medium',1,'Medium risk',TRUE,60,'{"risk_gte":45}'::jsonb,'{"approval_role":"analyst","approval_count":1,"sla_hours":72,"escalate_after_minutes":1440,"escalation_targets":["security_manager"]}'::jsonb,'system',NOW()),
            ('low',1,'Low risk',TRUE,10,'{}'::jsonb,'{"approval_role":"none","approval_count":0,"sla_hours":168,"escalate_after_minutes":2880,"escalation_targets":["analyst"]}'::jsonb,'system',NOW())
            ON CONFLICT (policy_id, version) DO NOTHING""",
    ]
    with schema_editor.connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)


class Migration(migrations.Migration):
    dependencies = [('enterprise', '0006_reportrecipientdelivery')]
    operations = [migrations.RunPython(create_security_workflow_schema, migrations.RunPython.noop)]
