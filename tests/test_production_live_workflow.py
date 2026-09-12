from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-live-deploy.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_live_production_workflow_is_manual_only_and_protected():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch"}

    jobs = data["jobs"]
    deploy = jobs["deploy-and-accept"]
    assert deploy["environment"] == "production"
    assert deploy["if"] == "github.ref == 'refs/heads/main'"
    assert data["concurrency"]["cancel-in-progress"] is False


def test_live_production_workflow_requires_pinned_ssh_and_exact_main():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "AEGIS_PRODUCTION_SSH_PRIVATE_KEY" in text
    assert "AEGIS_PRODUCTION_SSH_KNOWN_HOSTS" in text
    assert "production_remote_deploy.py" in text
    assert 'test "$(git rev-parse origin/main)" = "$GITHUB_SHA"' in text
    assert "StrictHostKeyChecking=no" not in text
    assert "PasswordAuthentication=yes" not in text


def test_live_production_workflow_runs_public_and_black_box_acceptance():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "public_acceptance.py" in text
    assert "external_black_box_e2e.py" in text
    assert "AEGIS_VERIFY_TLS: 'true'" in text
    assert "aegisscan.go-live-evidence.v1" in text
    assert "retention-days: 90" in text
