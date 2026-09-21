from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/production-final-governance.yml"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_final_governance_workflow_is_manual_or_chained_main_only_protected_and_internal_runner_bound():
    data = _workflow()
    triggers = data.get("on")
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch", "workflow_run"}
    assert triggers["workflow_run"]["workflows"] == ["Production Resilience Acceptance"]
    assert triggers["workflow_run"]["types"] == ["completed"]
    job = data["jobs"]["final-governance"]
    assert job["environment"] == "production"
    condition = job["if"]
    assert "workflow_dispatch" in condition
    assert "workflow_run.conclusion == 'success'" in condition
    assert "workflow_run.head_branch == 'main'" in condition
    assert "workflow_run.head_repository.full_name == github.repository" in condition
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "aegisscan-production"]
    assert data["concurrency"]["cancel-in-progress"] is False
    assert data["permissions"]["contents"] == "read"
    assert data["permissions"]["actions"] == "read"


def test_final_governance_requires_exact_main_same_sha_run_ids_and_enterprise_ca():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'test "${{ inputs.confirm }}" = "APPROVE"' in text
    assert 'test "$(git rev-parse HEAD)" = "$RELEASE_SHA"' in text
    assert 'test "$(git rev-parse origin/main)" = "$RELEASE_SHA"' in text
    assert "github.event.workflow_run.head_sha" in text
    assert "github.event.workflow_run.id" in text
    assert ".github/workflows/production-live-deploy.yml" in text
    assert ".github/workflows/supply-chain-release.yml" in text
    assert "LIVE_DEPLOY_RUN_ID" in text
    assert "RESILIENCE_RUN_ID" in text
    assert "SUPPLY_CHAIN_RUN_ID" in text
    assert "AEGIS_PRODUCTION_ENTERPRISE_CA_BUNDLE" in text
    assert "AEGIS_ENTERPRISE_CA_BUNDLE=/tmp/aegis-governance/enterprise-ca.pem" in text
    assert "REQUESTS_CA_BUNDLE=/tmp/aegis-governance/enterprise-ca.pem" in text
    assert "gh api" in text
    assert "gh run download" in text


def test_final_governance_revalidates_internal_surface_and_evidence_gate():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "aegisscan.go-live-evidence.v3" in text
    assert "internal_origin" in text
    assert "public_acceptance.py" in text
    assert "current-internal-acceptance.json" in text
    assert "--current-internal-acceptance" in text
    assert "production_governance_gate.py" in text
    assert "aegisscan.production-governance-decision.v2" in text
    assert "decision['decision'] == 'APPROVED'" in text
    assert "decision['deployment_mode'] == 'internal'" in text
    assert "sha256sum -c" in text


def test_final_governance_has_no_public_hosted_runner_or_public_origin_contract():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "runs-on: ubuntu-latest" not in text
    assert "AEGIS_APPROVED_PUBLIC_ORIGIN" not in text
    assert "current-public-acceptance.json" not in text
    assert "public_origin" not in text
    assert "Public origin:" not in text


def test_final_governance_cannot_mutate_release_or_repository():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "contents: write" not in text
    assert "gh release create" not in text
    assert "git tag" not in text
    assert "git push" not in text
    assert "curl -k" not in text
    assert "curl --insecure" not in text
    assert "retention-days: 90" in text


def test_final_governance_auto_chain_is_fail_closed_to_exact_repo_main_and_success():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'test "${{ github.event.workflow_run.name }}" = "Production Resilience Acceptance"' in text
    assert 'test "${{ github.event.workflow_run.conclusion }}" = "success"' in text
    assert 'test "${{ github.event.workflow_run.head_branch }}" = "main"' in text
    assert 'test "${{ github.event.workflow_run.head_repository.full_name }}" = "$GITHUB_REPOSITORY"' in text
    assert "run.get('head_sha') == release_sha" in text
    assert "run.get('head_branch') == 'main'" in text
    assert "repo.get('full_name') == repository" in text
    assert "{'push', 'workflow_dispatch'}" in text
    assert "{'push'}" in text
    assert "aegisscan-final-internal-governance-${{ env.RELEASE_SHA }}" in text
