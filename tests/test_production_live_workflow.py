from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-live-deploy.yml"
PROD_COMPOSE = ROOT / "aegis-platform/docker-compose.prod.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_live_production_workflow_has_only_manual_or_one_time_main_request_triggers():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch", "push"}
    assert triggers["push"]["branches"] == ["main"]
    assert triggers["push"]["paths"] == [".github/deployment-requests/internal-production.json"]

    jobs = data["jobs"]
    deploy = jobs["deploy-and-accept"]
    assert deploy["environment"] == "production"
    assert deploy["if"] == "github.ref == 'refs/heads/main'"
    assert deploy["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-production"]
    assert data["concurrency"]["cancel-in-progress"] is False


def test_live_production_workflow_pins_python_312_in_isolated_venv():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "uses: actions/setup-python@v6" in text
    assert "python-version: '3.12'" in text
    assert "command -v python" in text
    assert "sys.version_info[:2] != (3, 12)" in text
    assert 'python -m venv "$RUNNER_TEMP/aegis-production-venv"' in text
    assert 'echo "$RUNNER_TEMP/aegis-production-venv/bin" >> "$GITHUB_PATH"' in text
    assert "command -v python3" not in text


def test_live_production_workflow_requires_bounded_authorization_pinned_ssh_enterprise_ca_and_exact_main():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "production_deploy_request.py" in text
    assert "--event-before" in text
    assert ".github/deployment-requests/internal-production.json" in text
    assert "AEGIS_PRODUCTION_SSH_PRIVATE_KEY" in text
    assert "AEGIS_PRODUCTION_SSH_KNOWN_HOSTS" in text
    assert "AEGIS_PRODUCTION_ENTERPRISE_CA_BUNDLE" in text
    assert "AEGIS_ENTERPRISE_CA_BUNDLE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "REQUESTS_CA_BUNDLE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "SSL_CERT_FILE=/tmp/aegis-production/enterprise-ca.pem" in text
    assert "production_remote_deploy.py" in text
    assert 'test "$(git rev-parse origin/main)" = "$GITHUB_SHA"' in text
    assert "StrictHostKeyChecking=no" not in text
    assert "PasswordAuthentication=yes" not in text


def test_live_production_workflow_requires_operational_backup_alertmanager_black_box_and_cli_acceptance():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "production_remote_operational_acceptance.py" in text
    assert "operational-acceptance.json" in text
    assert "Alertmanager" in text
    assert "committed encrypted remote backup" in text
    assert "Verify internal HTTPS, private resolution, enterprise CA and security headers" in text
    assert "public_acceptance.py" in text
    assert "internal-acceptance.json" in text
    assert "Run real internal-network black-box production E2E" in text
    assert "external_black_box_e2e.py" in text
    assert "internal-black-box.log" in text
    assert "Prove installed CLI against internal production" in text
    assert "AEGIS_VERIFY_TLS: 'true'" in text
    assert "Generate one-run governed E2E identities" in text
    assert "::add-mask::" in text
    assert "AEGIS_E2E_EPHEMERAL_FIXTURE=true" in text
    assert "AEGIS_E2E_TARGET=aegis-scan-target" in text
    assert "Deactivate one-run E2E identities" in text
    assert "AEGIS_E2E_CLEANUP_ONLY" in text
    assert "e2e-cleanup.log" in text
    assert "AEGIS_PRODUCTION_E2E_" not in text
    assert "aegisscan.go-live-evidence.v3" in text
    assert "'deployment_mode': 'internal'" in text
    assert "'network_scope': 'rfc1918-or-ipv6-ula'" in text
    assert "'internal_origin':" in text
    assert "'enterprise_ca_sha256':" in text
    assert "'alertmanager_status':" in text
    assert "'backup_status':" in text
    assert "'backup_id':" in text
    assert "retention-days: 90" in text


def test_live_production_workflow_has_no_public_hosted_runner_or_public_evidence_contract():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "runs-on: ubuntu-latest" not in text
    assert "public_origin" not in text
    assert "public-acceptance.json" not in text
    assert "against public production" not in text
    assert "Verify public HTTPS" not in text

def test_production_validation_target_is_internal_only_and_explicitly_authorized():
    data = yaml.safe_load(PROD_COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    scan_target = data["services"]["scan_target"]
    assert scan_target["labels"]["aegisscan.production-validation-target"] == "true"
    assert "profiles" not in scan_target
    assert "ports" not in scan_target

    text = PROD_COMPOSE.read_text(encoding="utf-8")
    assert text.count('ALLOW_SINGLE_LABEL_SCAN_TARGETS: "1"') == 5
    assert text.count("aegis-scan-target") >= 7
    assert 'SCANNER_EGRESS_PRIVATE_TARGETS: "${SCANNER_EGRESS_PRIVATE_TARGETS:-},aegis-scan-target"' in text
