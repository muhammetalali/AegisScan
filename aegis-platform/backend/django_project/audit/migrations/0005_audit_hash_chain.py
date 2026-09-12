import hashlib
import json

from django.db import migrations, models


def _calculate_hash(entry, previous_hash):
    payload = {
        'id': str(entry.id),
        'chain_index': entry.chain_index,
        'previous_hash': previous_hash,
        'action': entry.action,
        'result': entry.result,
        'resource_type': entry.resource_type,
        'resource_id': entry.resource_id,
        'resource_repr': entry.resource_repr,
        'changes': entry.changes,
        'metadata': entry.metadata,
        'ip_address': str(entry.ip_address),
        'user_agent': entry.user_agent,
        'location': entry.location,
        'session_id': entry.session_id,
        'request_id': str(entry.request_id),
        'error_message': entry.error_message,
        'duration_ms': entry.duration_ms,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def backfill_chain(apps, schema_editor):
    AuditLog = apps.get_model('audit', 'AuditLog')
    previous_hash = ''
    for chain_index, entry in enumerate(AuditLog.objects.order_by('created_at', 'id').iterator(), start=1):
        entry.chain_index = chain_index
        entry_hash = _calculate_hash(entry, previous_hash)
        AuditLog.objects.filter(pk=entry.pk).update(
            chain_index=chain_index,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )
        previous_hash = entry_hash


class Migration(migrations.Migration):
    dependencies = [('audit', '0004_dataexport_artifact_sha256')]

    operations = [
        migrations.AddField(
            model_name='auditlog',
            name='chain_index',
            field=models.PositiveBigIntegerField(default=0, editable=False, verbose_name='chain index'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='auditlog',
            name='previous_hash',
            field=models.CharField(blank=True, default='', editable=False, max_length=64, verbose_name='previous entry hash'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='auditlog',
            name='entry_hash',
            field=models.CharField(blank=True, default='', editable=False, max_length=64, verbose_name='entry hash'),
            preserve_default=False,
        ),
        migrations.RunPython(backfill_chain, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='auditlog',
            name='chain_index',
            field=models.PositiveBigIntegerField(editable=False, unique=True, verbose_name='chain index'),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='entry_hash',
            field=models.CharField(editable=False, max_length=64, unique=True, verbose_name='entry hash'),
        ),
    ]
