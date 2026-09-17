from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-live-deploy.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_live_production_workflow_is_manual_only_protected_and_internal_runner_bound():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch"}

    jobs = data["jobs"]
    deploy = jobs["deploy-and-accept"]
    assert deploy["environment"] == "production"
    assert deploy["if"] == "github.ref == 'refs/heads/main'"
    assert deploy["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-production"]
    assert data["concurrency"]["cancel-in-progress"] is False


def test_live_production_workflow_requires_pinned_ssh_enterprise_ca_and_exact_main():
    text = WORKFLOW.read_text(encoding="utf-8")
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


def test_live_production_workflow_runs_internal_black_box_and_cli_acceptance():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "Verify internal HTTPS, private resolution, enterprise CA and security headers" in text
    assert "public_acceptance.py" in text
    assert "internal-acceptance.json" in text
    assert "Run real internal-network black-box production E2E" in text
    assert "external_black_box_e2e.py" in text
    assert "internal-black-box.log" in text
    assert "Prove installed CLI against internal production" in text
    assert "AEGIS_VERIFY_TLS: 'true'" in text
    assert "aegisscan.go-live-evidence.v2" in text
    assert "'deployment_mode': 'internal'" in text
    assert "'network_scope': 'rfc1918-or-ipv6-ula'" in text
    assert "'internal_origin':" in text
    assert "'enterprise_ca_sha256':" in text
    assert "retention-days: 90" in text


def test_live_production_workflow_has_no_public_hosted_runner_or_public_evidence_contract():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "runs-on: ubuntu-latest" not in text
    assert "public_origin" not in text
    assert "public-acceptance.json" not in text
    assert "against public production" not in text
    assert "Verify public HTTPS" not in text
