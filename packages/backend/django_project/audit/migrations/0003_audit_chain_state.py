from __future__ import annotations

import hashlib
import json

from django.db import migrations, models


GENESIS_HASH = "0" * 64


def _canonical(entry, previous_hash):
    return {
        "sequence": entry.sequence,
        "previous_hash": previous_hash,
        "action": entry.action,
        "result": entry.result,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "resource_repr": entry.resource_repr,
        "changes": entry.changes,
        "metadata": entry.metadata,
        "ip_address": entry.ip_address,
        "user_agent": entry.user_agent,
        "location": entry.location,
        "session_id": entry.session_id,
        "request_id": str(entry.request_id),
        "error_message": entry.error_message,
        "duration_ms": entry.duration_ms,
    }


def _hash(entry, previous_hash):
    payload = json.dumps(
        _canonical(entry, previous_hash),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def initialize_chain_state(apps, schema_editor):
    AuditLog = apps.get_model("audit", "AuditLog")
    ChainState = apps.get_model("audit", "AuditChainState")

    entries = list(AuditLog.objects.order_by("created_at", "id"))
    previous = GENESIS_HASH
    for sequence, entry in enumerate(entries, start=1):
        entry.sequence = sequence
        entry.previous_hash = previous
        entry.entry_hash = _hash(entry, previous)
        entry.save(update_fields=["sequence", "previous_hash", "entry_hash"])
        previous = entry.entry_hash

    ChainState.objects.create(id=1, last_sequence=len(entries), last_hash=previous)


class Migration(migrations.Migration):
    dependencies = [("audit", "0002_audit_chain")]

    operations = [
        migrations.CreateModel(
            name="AuditChainState",
            fields=[
                ("id", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("last_sequence", models.PositiveBigIntegerField(default=0, editable=False)),
                ("last_hash", models.CharField(default=GENESIS_HASH, editable=False, max_length=64)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Audit Chain State",
                "verbose_name_plural": "Audit Chain State",
            },
        ),
        migrations.RunPython(initialize_chain_state, migrations.RunPython.noop),
    ]
