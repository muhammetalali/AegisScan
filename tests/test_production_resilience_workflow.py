from pathlib import Path
import json

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


def test_resilience_workflow_keeps_backup_secrets_on_host_and_consumes_restore_proof():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "production_resilience_backup.py" in text
    for forbidden in (
        "AEGIS_PRODUCTION_BACKUP_S3_ENDPOINT",
        "AEGIS_PRODUCTION_BACKUP_S3_BUCKET",
        "AEGIS_PRODUCTION_BACKUP_S3_CREDENTIALS_JSON",
        "AEGIS_PRODUCTION_BACKUP_ENCRYPTION_KEY_B64",
        "BACKUP_CREDENTIALS_JSON",
        "BACKUP_ENCRYPTION_KEY_B64",
    ):
        assert forbidden not in text
    assert "services:\n      postgres:" not in text
    assert "remote_backup.py restore" not in text
    assert "--network host" not in text
    assert "restore_verification" in text
    assert "AEGIS_DR_SOURCE_SHA256" in text
    assert "'source_sha256': os.environ['AEGIS_DR_SOURCE_SHA256']" in text
    assert "postgres_restore_verified" in text
    assert "isolated-backup-db" in text
    assert "ephemeral-backup-container-tmpfs" in text
    assert "postgres_image_id" in text
    assert "aegisscan.production-host-restore-verification.v1" in text
    assert "restored-and-verified-on-production-host" in text
    assert "RESTORE_VERIFICATION=PASS scope=production-host-disposable-postgres" in text
    assert "for command_name in git ssh ssh-keygen python3; do" in text


def test_resilience_workflow_reuses_authenticated_internal_alert_delivery_proof():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "AEGIS_PRODUCTION_ALERT_WEBHOOK_URL" not in text
    assert "aegis-alertmanager:resilience" not in text
    assert "Prove authenticated internal alert delivery after recovery" in text
    assert "payload.get('recovery')" in text
    assert "remote.get('alert_delivery')" in text
    assert "delivery.get('authenticated') is not True" in text
    assert "delivery.get('transport') != 'https'" in text
    assert "delivery.get('receiver') != 'internal'" in text
    assert "delivery.get('proof_alertname') != 'AegisProductionAlertDeliveryAcceptance'" in text
    assert "delivery.get('proof_release_sha') != payload.get('release_sha')" in text
    assert "audit_payload_sha256" in text
    assert "proof_acceptance_id" in text
    assert "external-alert-delivery.json" in text
    assert "aegis_alert_receiver_events_total" in text
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


def test_restore_evidence_preserves_its_declared_schema_and_status(tmp_path, monkeypatch):
    steps = _workflow()['jobs']['resilience-acceptance']['steps']
    step = next(s for s in steps if s.get('name') == 'Trigger fresh exact-release backup and host-owned restore drill')
    source = step['run'].split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    source = source.replace('/tmp/aegis-resilience', str(tmp_path))
    verification = {
        'status': 'success', 'postgres_restore_verified': True,
        'network_scope': 'isolated-backup-db',
        'plaintext_scope': 'ephemeral-backup-container-tmpfs',
        'postgres_image_id': 'sha256:' + 'a' * 64,
        'backup_id': 'backup-1', 'manifest_version_id': 'manifest-1',
        'object_version_id': 'object-1', 'source_sha256': 'b' * 64,
    }
    backup = {**verification, 'restore_verification': verification}
    (tmp_path / 'remote-backup.json').write_text(json.dumps({
        'schema': 'aegisscan.production-resilience-backup.v1', 'status': 'success', 'backup': backup,
    }) + '\n')
    monkeypatch.setenv('GITHUB_ENV', str(tmp_path / 'github-env'))
    exec(compile(source, '<restore-evidence-step>', 'exec'), {})
    record = json.loads((tmp_path / 'remote-restore.json').read_text())
    assert record['schema'] == 'aegisscan.production-host-restore-verification.v1'
    assert record['status'] == 'restored-and-verified-on-production-host'
    assert record['source_sha256'] == verification['source_sha256']
    assert record['postgres_restore_verified'] is True
