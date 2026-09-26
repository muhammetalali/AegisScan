from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-resilience-acceptance.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_resilience_workflow_is_manual_or_chained_main_only_and_protected():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch", "workflow_run"}
    assert triggers["workflow_run"]["workflows"] == ["Internal Production Deploy and Acceptance"]
    assert triggers["workflow_run"]["types"] == ["completed"]
    job = data["jobs"]["resilience-acceptance"]
    assert job["environment"] == "production"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-resilience"]
    condition = job["if"]
    assert "workflow_dispatch" in condition
    assert "workflow_run.conclusion == 'success'" in condition
    assert "workflow_run.head_branch == 'main'" in condition
    assert "workflow_run.head_repository.full_name == github.repository" in condition
    assert data["concurrency"]["cancel-in-progress"] is False
    assert "runs-on: ubuntu-latest" not in WORKFLOW.read_text(encoding="utf-8")


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
    assert "sudo apt-get" not in text
    assert "Verify provisioned resilience dependencies" in text
    assert "hashlib.sha256" in text
    assert "retention-days: 90" in text


def test_resilience_chaining_preserves_exact_release_sha():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "RELEASE_SHA:" in text
    assert "github.event.workflow_run.head_sha" in text
    assert 'test "$(git rev-parse HEAD)" = "$RELEASE_SHA"' in text
    assert 'test "$(git rev-parse origin/main)" = "$RELEASE_SHA"' in text
    assert '--release-sha "$RELEASE_SHA"' in text
    assert "aegisscan-production-resilience-${{ env.RELEASE_SHA }}" in text


def test_resilience_includes_service_recovery_and_validates_openssh_key():
    data = _workflow()
    steps = data['jobs']['resilience-acceptance']['steps']
    recovery = next(s for s in steps if s.get('name') == 'Recover the production API and verify HTTPS and scanner health')
    assert '--action recover-services' in recovery['run']
    assert '--release-sha "$RELEASE_SHA"' in recovery['run']
    text = WORKFLOW.read_text()
    assert "printf '%s\\n' \"$PROD_SSH_PRIVATE_KEY\"" in text
    assert 'ssh-keygen -y -f /tmp/aegis-resilience/id >/dev/null' in text
    assert "'service-recovery.json'," in text
