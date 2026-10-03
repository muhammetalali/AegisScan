from django.db import migrations


def install(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute("""
        CREATE FUNCTION aegis_web_lab_evidence_immutable() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.source IN ('lab_runtime_inspector', 'lab_verification') THEN
                RAISE EXCEPTION 'Web Labs evidence is immutable';
            END IF;
            IF TG_OP = 'UPDATE' THEN
                IF NEW.source IN ('lab_runtime_inspector', 'lab_verification') THEN
                    RAISE EXCEPTION 'Web Labs evidence is immutable';
                END IF;
                RETURN NEW;
            END IF;
            RETURN OLD;
        END;
        $$;
        CREATE TRIGGER trg_web_lab_evidence_immutable
        BEFORE UPDATE OR DELETE ON evidence_evidence
        FOR EACH ROW EXECUTE FUNCTION aegis_web_lab_evidence_immutable();
    """)


def remove(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    schema_editor.execute('DROP TRIGGER IF EXISTS trg_web_lab_evidence_immutable ON evidence_evidence;')
    schema_editor.execute('DROP FUNCTION IF EXISTS aegis_web_lab_evidence_immutable();')


class Migration(migrations.Migration):
    dependencies = [('enterprise', '0049_burp_invocation_claims')]
    operations = [migrations.RunPython(install, remove)]
