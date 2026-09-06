import django.db.models.deletion
from django.db import migrations, models


def adopt_or_create_action_tables(apps, schema_editor):
    DecisionAction = apps.get_model('enterprise', 'DecisionAction')
    DecisionActionEvent = apps.get_model('enterprise', 'DecisionActionEvent')
    if schema_editor.connection.vendor != 'postgresql':
        schema_editor.create_model(DecisionAction)
        schema_editor.create_model(DecisionActionEvent)
        return
    schema_editor.execute(
        'CREATE INDEX IF NOT EXISTS idx_actions_requested_by '
        'ON security_decision_actions(requested_by)'
    )
    schema_editor.execute('DROP INDEX IF EXISTS idx_action_events_action_id_created')
    schema_editor.execute(
        'CREATE INDEX IF NOT EXISTS idx_action_events_created '
        'ON security_decision_action_events(action_id, created_at)'
    )


def reverse_action_table_adoption(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        schema_editor.delete_model(apps.get_model('enterprise', 'DecisionActionEvent'))
        schema_editor.delete_model(apps.get_model('enterprise', 'DecisionAction'))
        return
    schema_editor.execute('DROP INDEX IF EXISTS idx_actions_requested_by')
    schema_editor.execute('DROP INDEX IF EXISTS idx_action_events_created')
    schema_editor.execute(
        'CREATE INDEX IF NOT EXISTS idx_action_events_action_id_created '
        'ON security_decision_action_events(action_id, created_at)'
    )


class Migration(migrations.Migration):
    dependencies = [('enterprise', '0007_security_workflow_schema_ownership')]
    operations = [migrations.SeparateDatabaseAndState(database_operations=[],state_operations=[
        migrations.CreateModel(name='DecisionAction',fields=[
            ('action_id',models.CharField(max_length=255,primary_key=True,serialize=False)),('decision_id',models.TextField()),
            ('node_id',models.TextField()),('title',models.TextField()),('owner',models.TextField()),('requested_by',models.TextField()),
            ('sla_hours',models.PositiveIntegerField()),('state',models.TextField()),('risk_before',models.IntegerField(default=0)),
            ('confidence_before',models.IntegerField(default=0)),('priority',models.IntegerField(default=0)),('recommended_action',models.TextField()),
            ('remediation_plan',models.JSONField(default=list)),('created_at',models.DateTimeField()),('updated_at',models.DateTimeField()),
            ('version',models.PositiveIntegerField(default=1)),('sla_status',models.TextField(default='on_track')),('escalation_level',models.PositiveIntegerField(default=0)),
        ],options={'db_table':'security_decision_actions','indexes':[models.Index(fields=['state','updated_at'],name='idx_actions_state_updated'),models.Index(fields=['owner','sla_status','created_at'],name='idx_actions_owner_sla'),models.Index(fields=['requested_by'],name='idx_actions_requested_by')]}),
        migrations.CreateModel(name='DecisionActionEvent',fields=[
            ('event_id',models.BigAutoField(primary_key=True,serialize=False)),('event_type',models.TextField()),('actor',models.TextField()),
            ('note',models.TextField(blank=True,null=True)),('created_at',models.DateTimeField()),
            ('action',models.ForeignKey(db_column='action_id',on_delete=django.db.models.deletion.CASCADE,related_name='events',to='enterprise.decisionaction')),
        ],options={'db_table':'security_decision_action_events','ordering':['event_id'],'indexes':[models.Index(fields=['action','created_at'],name='idx_action_events_created')]}),
    ]), migrations.RunPython(adopt_or_create_action_tables, reverse_action_table_adoption)]
