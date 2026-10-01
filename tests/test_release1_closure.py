from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.release1_closure import (
    REQUIRED_RUNS,
    ReleaseClosureError,
    build_manifest,
)

from tests.release1_evidence_fixture import REPO, SHA, _build, _fixture, _write


def test_release1_closure_requires_complete_exact_sha_evidence(tmp_path: Path):
    payload = _build(tmp_path)

    assert payload["schema"] == "aegisscan.release1-closure.v1"
    assert payload["status"] == "success"
    assert payload["decision"] == "RELEASED"
    assert payload["release"] == "1"
    assert payload["release_sha"] == SHA
    assert all(payload["controls"].values())
    assert set(payload["workflow_runs"]) == set(REQUIRED_RUNS)
    assert set(payload["evidence"]["supply_chain"]) == {
        "django.cdx.json",
        "django.provenance.json",
        "fastapi.cdx.json",
        "fastapi.provenance.json",
        "frontend.cdx.json",
        "frontend.provenance.json",
    }
    assert len(payload["release_closure_sha256"]) == 64


def test_release1_closure_fails_closed_on_wrong_workflow_sha(tmp_path: Path):
    metadata, evidence, repository_state, branch_hygiene = _fixture(tmp_path)
    first = next(metadata.glob("*.json"))
    payload = json.loads(first.read_text())
    payload["head_sha"] = "f" * 40
    first.write_text(json.dumps(payload))

    with pytest.raises(ReleaseClosureError, match="workflow metadata failed checks"):
        build_manifest(
            release_sha=SHA,
            repository=REPO,
            metadata_root=metadata,
            evidence_root=evidence,
            repository_state=repository_state,
            branch_hygiene=branch_hygiene,
            output=tmp_path / "release1.json",
        )


def test_release1_closure_requires_zero_open_pull_requests(tmp_path: Path):
    metadata, evidence, repository_state, branch_hygiene = _fixture(tmp_path)
    state = json.loads(repository_state.read_text())
    state["open_pr_count"] = 1
    repository_state.write_text(json.dumps(state))

    with pytest.raises(ReleaseClosureError, match="zero open pull requests"):
        build_manifest(
            release_sha=SHA,
            repository=REPO,
            metadata_root=metadata,
            evidence_root=evidence,
            repository_state=repository_state,
            branch_hygiene=branch_hygiene,
            output=tmp_path / "release1.json",
        )


def test_release1_closure_requires_branch_hygiene_to_apply_all_safe_candidates(tmp_path: Path):
    metadata, evidence, repository_state, branch_hygiene = _fixture(tmp_path)
    hygiene = json.loads(branch_hygiene.read_text())
    hygiene["deleted"] = []
    branch_hygiene.write_text(json.dumps(hygiene))

    with pytest.raises(ReleaseClosureError, match="did not close every safe merged candidate"):
        build_manifest(
            release_sha=SHA,
            repository=REPO,
            metadata_root=metadata,
            evidence_root=evidence,
            repository_state=repository_state,
            branch_hygiene=branch_hygiene,
            output=tmp_path / "release1.json",
        )


def test_release1_closure_rejects_stale_production_governance(tmp_path: Path):
    metadata, evidence, repository_state, branch_hygiene = _fixture(tmp_path)
    decision = evidence / "decision.json"
    payload = json.loads(decision.read_text())
    payload["release_sha"] = "e" * 40
    decision.write_text(json.dumps(payload))

    with pytest.raises(ReleaseClosureError, match="production governance release SHA mismatch"):
        build_manifest(
            release_sha=SHA,
            repository=REPO,
            metadata_root=metadata,
            evidence_root=evidence,
            repository_state=repository_state,
            branch_hygiene=branch_hygiene,
            output=tmp_path / "release1.json",
        )


@pytest.mark.parametrize('mutation', ['missing', 'skipped', 'wrong_attempt', 'wrong_sha', 'wrong_name'])
def test_closure_rejects_green_workflow_without_required_executed_job(tmp_path, mutation):
    metadata, evidence, state, hygiene = _fixture(tmp_path)
    path = next(p for p in metadata.glob('*.json') if json.loads(p.read_text())['name'] == 'Final Internal Production Governance')
    run = json.loads(path.read_text())
    if mutation == 'missing':
        run.pop('jobs')
    else:
        field, value = {
            'skipped': ('conclusion', 'skipped'), 'wrong_attempt': ('run_attempt', 2),
            'wrong_sha': ('head_sha', 'f' * 40), 'wrong_name': ('name', 'contract-only'),
        }[mutation]
        run['jobs'][0][field] = value
    _write(path, run)
    with pytest.raises(ReleaseClosureError, match='job'):
        build_manifest(release_sha=SHA, repository=REPO, metadata_root=metadata,
                       evidence_root=evidence, repository_state=state, branch_hygiene=hygiene,
                       output=tmp_path / 'closure.json')


def test_closure_rejects_other_release_provenance(tmp_path):
    metadata, evidence, state, hygiene = _fixture(tmp_path)
    path = evidence / 'django.provenance.json'
    provenance = json.loads(path.read_text())
    provenance['invocation']['configSource']['digest']['sha1'] = 'f' * 40
    _write(path, provenance)
    with pytest.raises(ReleaseClosureError, match='provenance does not match'):
        build_manifest(release_sha=SHA, repository=REPO, metadata_root=metadata,
                       evidence_root=evidence, repository_state=state, branch_hygiene=hygiene,
                       output=tmp_path / 'closure.json')



def test_release_workflow_publishes_exact_sha_immutable_github_release_only_after_closure():
    import yaml
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load((root / '.github/workflows/release1-closure.yml').read_text(encoding='utf-8'))
    assert any('python scripts/ci/release1_version.py >> "$GITHUB_ENV"' in step.get('run', '') for step in workflow['jobs']['release1-closure']['steps'])
    steps = workflow['jobs']['release1-closure']['steps']
    names = [step.get('name') for step in steps]
    prove = names.index('Prove Release 1 decision')
    publish = names.index('Publish immutable GitHub Release 1 evidence')
    retain = names.index('Retain Release 1 closure evidence')
    assert prove < publish < retain
    script = steps[publish]['run']
    assert 'gh release create "$AEGIS_RELEASE_TAG"' in script
    assert '--target "$AEGIS_RELEASE_SHA"' in script
    assert 'release1-closure.json' in script
    assert 'release1-closure.sha256' in script
    assert "obj.get('type') != 'commit'" in script
    assert "obj.get('sha') != expected_sha" in script
    assert "release.get('targetCommitish') != expected_sha" in script
    assert 'isDraft' in script and 'isPrerelease' in script
    assert 'cmp artifacts/release1-closure.json' in script
    assert 'cmp artifacts/release1-closure.sha256' in script


def test_contract_success_cannot_be_reported_as_actual_release_closure(tmp_path):
    import os
    import subprocess
    import yaml
    root = Path(__file__).parents[1]
    live = yaml.safe_load((root / '.github/workflows/release1-closure.yml').read_text())
    contract = yaml.safe_load((root / '.github/workflows/release1-contract-reality.yml').read_text())
    assert set(live['on']) == {'workflow_run', 'workflow_dispatch'}
    assert set(contract['on']) == {'pull_request', 'push'}
    result = live['jobs']['release-result']
    assert result['if'] == 'always()'
    assert set(result['needs']) == {'release-contract', 'release1-closure'}
    script = result['steps'][0]['run']
    for outcome in ['skipped', 'failure', 'cancelled', 'success']:
        summary = tmp_path / f'{outcome}.txt'
        proc = subprocess.run(['bash', '-c', script], env={**os.environ,
            'CONTRACT_RESULT': 'success', 'CLOSURE_RESULT': outcome,
            'GITHUB_STEP_SUMMARY': str(summary)}, capture_output=True, text=True)
        assert (proc.returncode == 0) is (outcome == 'success')
        assert ('AEGISSCAN_RELEASE_1=CLOSED' in summary.read_text()) is (outcome == 'success')
