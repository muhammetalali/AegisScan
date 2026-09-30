from pathlib import Path

import json
import os
import subprocess
import zipfile

import pytest
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


@pytest.mark.parametrize("workflow", ["governance", "closure"])
@pytest.mark.parametrize("missing_component", [False, True])
def test_evidence_download_requires_all_exact_release_supply_artifacts_and_skips_build_records(
    tmp_path, workflow, missing_component
):
    """Execute the real shell steps against a CLI fixture with ZIPs and a raw build record."""
    release = "a" * 40
    inventory = {}
    for run_id in ("1", "2", "11", "12", "13"):
        archive = tmp_path / f"run-{run_id}.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("manifest.json", "{}")
        inventory[run_id] = {f"evidence-{run_id}": str(archive)}
    inventory["3"] = {}
    expected = [f"supply-chain-{component}-{release}" for component in ("django", "fastapi", "frontend")]
    for component, name in zip(("django", "fastapi", "frontend"), expected):
        if missing_component and component == "fastapi":
            continue
        archive = tmp_path / f"{component}.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr(f"{component}.cdx.json", "{}")
            stream.writestr(f"{component}.provenance.json", "{}")
        inventory["3"][name] = str(archive)
    raw = tmp_path / "build.dockerbuild"
    raw.write_bytes(b"Docker build record: deliberately not a ZIP")
    inventory["3"]["owner~repo~record.dockerbuild"] = str(raw)
    fixture = tmp_path / "inventory.json"
    fixture.write_text(json.dumps(inventory))
    trace = tmp_path / "trace.jsonl"
    binary = tmp_path / "bin"
    binary.mkdir()
    cli = binary / "gh"
    cli.write_text('''#!/usr/bin/env python3
import json, os, sys, zipfile
from pathlib import Path
args = sys.argv[1:]
if args[0] == 'api':
    print('{}')
    sys.exit(0)
assert args[:2] == ['run', 'download'], args
run_id = args[2]
available = json.loads(Path(os.environ['GH_FIXTURE']).read_text())[run_id]
names = [args[i+1] for i, arg in enumerate(args) if arg == '--name']
selected = names or list(available)
if any(name not in available for name in selected):
    sys.exit('required artifact missing')
with open(os.environ['GH_TRACE'], 'a') as stream:
    stream.write(json.dumps({'run': run_id, 'selected': selected}) + '\\n')
root = Path(args[args.index('--dir') + 1])
for name in selected:
    with zipfile.ZipFile(available[name]) as archive:
        archive.extractall(root / name)
''')
    cli.chmod(0o755)
    if workflow == "governance":
        steps = _workflow()["jobs"]["final-governance"]["steps"]
        title = "Download independently captured workflow metadata and evidence"
        prefix = "/tmp/aegis-governance"
    else:
        data = yaml.safe_load((ROOT / ".github/workflows/release1-closure.yml").read_text())
        steps = data["jobs"]["release1-closure"]["steps"]
        title = "Download immutable release evidence"
        prefix = "/tmp/release1"
    root = tmp_path / "output"
    script = next(step["run"] for step in steps if step.get("name") == title).replace(prefix, str(root))
    env = {
        **os.environ, "PATH": f"{binary}:{os.environ['PATH']}",
        "GH_FIXTURE": str(fixture), "GH_TRACE": str(trace),
        "GITHUB_REPOSITORY": "owner/repo", "RELEASE_SHA": release, "AEGIS_RELEASE_SHA": release,
        "LIVE_DEPLOY_RUN_ID": "1", "RESILIENCE_RUN_ID": "2", "SUPPLY_CHAIN_RUN_ID": "3",
        "FINAL_ACCEPTANCE_RUN_ID": "11", "FINAL_GOVERNANCE_RUN_ID": "12",
        "FINAL_PRODUCTION_GOVERNANCE_RUN_ID": "13",
    }
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    if missing_component:
        assert result.returncode != 0
        assert "required artifact missing" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        calls = [json.loads(line) for line in trace.read_text().splitlines()]
        supply = [call for call in calls if call["run"] == "3"]
        assert len(supply) == 3
        assert all(len(call["selected"]) == 1 for call in supply)
        assert [call["selected"][0] for call in supply] == expected
        for component in ("django", "fastapi", "frontend"):
            assert len(list(root.rglob(f"{component}.cdx.json"))) == 1
            assert len(list(root.rglob(f"{component}.provenance.json"))) == 1
