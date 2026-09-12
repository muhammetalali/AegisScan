from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-final-governance.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_final_governance_workflow_is_manual_main_only_and_protected():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch"}
    job = data["jobs"]["final-governance"]
    assert job["environment"] == "production"
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert data["concurrency"]["cancel-in-progress"] is False
    assert data["permissions"]["contents"] == "read"
    assert data["permissions"]["actions"] == "read"


def test_final_governance_requires_exact_main_and_three_independent_run_ids():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'test "${{ inputs.confirm }}" = "APPROVE"' in text
    assert 'test "$RELEASE_SHA" = "$GITHUB_SHA"' in text
    assert 'test "$(git rev-parse origin/main)" = "$GITHUB_SHA"' in text
    assert "LIVE_DEPLOY_RUN_ID" in text
    assert "RESILIENCE_RUN_ID" in text
    assert "SUPPLY_CHAIN_RUN_ID" in text
    assert "gh api" in text
    assert "gh run download" in text


def test_final_governance_revalidates_public_surface_and_evidence_gate():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "public_acceptance.py" in text
    assert "production_governance_gate.py" in text
    assert "aegisscan.production-governance-decision.v1" in text
    assert "decision['decision'] == 'APPROVED'" in text
    assert "sha256sum -c" in text


def test_final_governance_cannot_mutate_release_or_repository():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "contents: write" not in text
    assert "gh release create" not in text
    assert "git tag" not in text
    assert "git push" not in text
    assert "curl -k" not in text
    assert "curl --insecure" not in text
    assert "retention-days: 90" in text
