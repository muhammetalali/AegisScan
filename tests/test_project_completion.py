from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.project_completion import ProjectCompletionError, build_completion

SHA = "a" * 40
REPO = "muhammetalali/AegisScan"


def _write(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _fixture(tmp_path: Path):
    state = _write(
        tmp_path / "state.json",
        {"repository": REPO, "default_branch": "main", "main_sha": SHA, "open_pr_count": 0},
    )
    release = _write(
        tmp_path / "release.json",
        {"tagName": "v1.0.0", "targetCommitish": SHA, "isDraft": False, "isPrerelease": False},
    )
    tag = _write(
        tmp_path / "tag.json",
        {"ref": "refs/tags/v1.0.0", "object": {"type": "commit", "sha": SHA}},
    )
    run = _write(
        tmp_path / "run.json",
        {
            "id": 42,
            "run_attempt": 1,
            "name": "Fresh Main Final Verification",
            "path": ".github/workflows/fresh-main-final-verification.yml",
            "status": "completed",
            "conclusion": "success",
            "head_sha": SHA,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "repository": {"full_name": REPO},
        },
    )
    verification = _write(
        tmp_path / "fresh-main-final-verification.json",
        {
            "schema": "aegisscan.fresh-main-final-verification.v1",
            "status": "success",
            "decision": "VERIFIED",
            "repository": REPO,
            "release": 1,
            "release_tag": "v1.0.0",
            "release_sha": SHA,
            "main_sha": SHA,
            "open_pr_count": 0,
            "controls": {
                "fresh_main_exact_release_sha": True,
                "required_ci_success": True,
                "release1_released": True,
                "github_release_exact_tag": True,
                "external_providers_accepted": True,
                "release_performance_accepted": True,
                "final_hygiene_clean": True,
                "zero_open_prs": True,
                "zero_sha_drift": True,
            },
            "verification_sha256": "b" * 64,
        },
    )
    return state, release, tag, run, verification


def _build(tmp_path: Path):
    state, release, tag, run, verification = _fixture(tmp_path)
    return build_completion(
        release_sha=SHA,
        repository=REPO,
        repository_state=state,
        release_metadata=release,
        release_tag_metadata=tag,
        verification_run_metadata=run,
        fresh_verification=verification,
        output=tmp_path / "completion.json",
    )


def test_project_completion_requires_authoritative_fresh_main_verification(tmp_path: Path):
    payload = _build(tmp_path)
    assert payload["schema"] == "aegisscan.project-completion.v1"
    assert payload["status"] == "success"
    assert payload["decision"] == "PROJECT_COMPLETE"
    assert payload["project"] == "AegisScan"
    assert payload["canonical_application"] == "aegis-platform/"
    assert payload["canonical_branch"] == "main"
    assert payload["release_sha"] == payload["main_sha"] == SHA
    assert payload["open_pr_count"] == 0
    assert payload["fresh_main_verification"]["run_id"] == 42
    assert all(payload["controls"].values())
    assert len(payload["completion_sha256"]) == 64


def test_project_completion_rejects_missing_provider_acceptance_control(tmp_path: Path):
    state, release, tag, run, verification = _fixture(tmp_path)
    value = json.loads(verification.read_text())
    value["controls"]["external_providers_accepted"] = False
    verification.write_text(json.dumps(value))
    with pytest.raises(ProjectCompletionError, match="not authoritative"):
        build_completion(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            verification_run_metadata=run, fresh_verification=verification,
            output=tmp_path / "completion.json",
        )


def test_project_completion_rejects_verification_run_from_other_sha(tmp_path: Path):
    state, release, tag, run, verification = _fixture(tmp_path)
    value = json.loads(run.read_text())
    value["head_sha"] = "f" * 40
    run.write_text(json.dumps(value))
    with pytest.raises(ProjectCompletionError, match="workflow metadata"):
        build_completion(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            verification_run_metadata=run, fresh_verification=verification,
            output=tmp_path / "completion.json",
        )


def test_project_completion_rejects_release_tag_drift(tmp_path: Path):
    state, release, tag, run, verification = _fixture(tmp_path)
    value = json.loads(release.read_text())
    value["targetCommitish"] = "e" * 40
    release.write_text(json.dumps(value))
    with pytest.raises(ProjectCompletionError, match="Release 1"):
        build_completion(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            verification_run_metadata=run, fresh_verification=verification,
            output=tmp_path / "completion.json",
        )


def test_project_completion_workflow_runs_only_after_verified_fresh_main_and_publishes_attestation():
    import yaml
    root = Path(__file__).parents[1]
    path = root / ".github/workflows/project-completion.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "workflow_run" in workflow["on"]
    assert workflow["on"]["workflow_run"]["workflows"] == ["Fresh Main Final Verification"]
    job = workflow["jobs"]["project-completion"]
    assert "github.event.workflow_run.conclusion == 'success'" in job["if"]
    text = path.read_text(encoding="utf-8")
    assert "project_completion.py" in text
    assert "AEGISSCAN_PROJECT=COMPLETE" in text
    assert "gh release upload v1.0.0" in text
    assert "aegisscan-project-completion.json" in text
    assert "partial project-completion asset set; refusing overwrite" in text
    assert "--clobber" not in text
    assert "cmp artifacts/aegisscan-project-completion.json" in text
