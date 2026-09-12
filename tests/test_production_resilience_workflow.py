from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-resilience-acceptance.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_resilience_workflow_is_manual_main_only_and_protected():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch"}
    job = data["jobs"]["resilience-acceptance"]
    assert job["environment"] == "production"
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert data["concurrency"]["cancel-in-progress"] is False


def test_resilience_workflow_pins_remote_backup_versions_and_restores_disposable_db():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "production_resilience_backup.py" in text
    assert "--manifest-version-id" in text
    assert "AEGIS_DR_OBJECT_VERSION_ID" in text
    assert "verify_postgres_restore.sh" in text
    assert "postgres:16-alpine" in text
    assert "resilience-restore-password" in text
    assert "RESTORE_VERIFICATION=PASS" in text
    assert "dropdb" not in text
    assert "PGHOST: 127.0.0.1" in text


def test_resilience_workflow_uses_real_alertmanager_external_route():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "aegis-alertmanager:resilience" in text
    assert "ALERT_WEBHOOK_URL" in text
    assert "/api/v2/alerts" in text
    assert "alertmanager_notifications_total" in text
    assert "alertmanager_notifications_failed_total" in text
    assert "https://*)" in text
    assert "curl -k" not in text
    assert "curl --insecure" not in text


def test_resilience_workflow_keeps_ssh_pinned_and_evidence_hashed():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "AEGIS_PRODUCTION_SSH_KNOWN_HOSTS" in text
    assert "AEGIS_PRODUCTION_SSH_PRIVATE_KEY" in text
    assert "StrictHostKeyChecking=no" not in text
    assert "PasswordAuthentication=yes" not in text
    assert "aegisscan.production-resilience-evidence.v1" in text
    assert "hashlib.sha256" in text
    assert "retention-days: 90" in text
