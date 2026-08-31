from django.db import migrations


def backfill_collector_engine(apps, schema_editor):
    VulnerabilityEvidence = apps.get_model("vulnerabilities", "VulnerabilityEvidence")
    for evidence in VulnerabilityEvidence.objects.exclude(raw_data="").only("pk", "raw_data", "source", "metadata"):
        collector = ""
        raw = evidence.raw_data
        if isinstance(raw, str):
            try:
                import json
                raw = json.loads(raw)
            except (TypeError, ValueError):
                raw = {}
        if isinstance(raw, dict):
            collector = str(raw.get("engine") or raw.get("collector_engine") or "").strip()
        if not collector:
            metadata = evidence.metadata or {}
            collector = str(metadata.get("collector_engine") or "").strip()
        if not collector:
            collector = str(evidence.source or "").strip()
        if collector and evidence.collector_engine != collector:
            VulnerabilityEvidence.objects.filter(pk=evidence.pk).update(collector_engine=collector)


def noop_reverse(apps, schema_editor):
    # Provenance backfill is intentionally irreversible; raw_data remains the source of truth.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0003_evidence_collector_engine"),
    ]

    operations = [
        migrations.RunPython(backfill_collector_engine, noop_reverse),
    ]
