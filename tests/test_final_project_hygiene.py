from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.release1_version import RELEASE_TAG

from scripts.ci.final_project_hygiene import FinalHygieneError, build_hygiene

SHA = "a" * 40
REPO = "muhammetalali/AegisScan"


def _write(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _fixture(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _write(
        repo_root / ".github/deployment-requests/internal-production.json",
        {
            "schema": "aegisscan.internal-production-deployment-request.v1",
            "request_id": "historical-release-request",
            "confirm": "DEPLOY",
            "deployment_mode": "internal",
            "requested_branch": "main",
            "requested_base_sha": "b" * 40,
            "requested_at": "2026-09-27T13:00:00Z",
            "expires_at": "2026-09-27T21:00:00Z",
        },
    )
    state = _write(
        tmp_path / "repository-state.json",
        {
            "repository": REPO,
            "default_branch": "main",
            "main_sha": SHA,
            "open_pr_count": 0,
        },
    )
    inventory = [
        {"name": "main", "sha": SHA, "category": "default_branch", "deletable": False},
        {"name": "archive/history", "sha": "c" * 40, "category": "historical_archive", "deletable": False},
        {"name": "backup/safety", "sha": "d" * 40, "category": "safety_backup", "deletable": False},
    ]
    apply_result = _write(
        tmp_path / "apply.json",
        {
            "plan": {
                "schema": "aegis.branch-hygiene-plan.v1",
                "repository": REPO,
                "default_branch": "main",
                "default_sha": SHA,
                "min_age_hours": 24,
                "include_chatgpt_b": True,
                "open_pr_heads": [],
                "inventory": inventory + [
                    {"name": "codex/merged", "sha": "e" * 40, "category": "safe_merged_candidate", "deletable": True}
                ],
                "delete_candidates": ["codex/merged"],
            },
            "deleted": [{"name": "codex/merged", "sha": "e" * 40}],
        },
    )
    post_plan = _write(
        tmp_path / "post.json",
        {
            "plan": {
                "schema": "aegis.branch-hygiene-plan.v1",
                "repository": REPO,
                "default_branch": "main",
                "default_sha": SHA,
                "min_age_hours": 24,
                "include_chatgpt_b": True,
                "open_pr_heads": [],
                "inventory": inventory,
                "delete_candidates": [],
            },
            "deleted": [],
        },
    )
    release = _write(
        tmp_path / "release.json",
        {
            "tagName": RELEASE_TAG,
            "targetCommitish": SHA,
            "isDraft": False,
            "isPrerelease": False,
            "url": f"https://github.com/muhammetalali/AegisScan/releases/tag/{RELEASE_TAG}",
        },
    )
    return repo_root, state, apply_result, post_plan, release


def _build(tmp_path: Path):
    repo_root, state, apply_result, post_plan, release = _fixture(tmp_path)
    return build_hygiene(
        release_sha=SHA,
        repository=REPO,
        repo_root=repo_root,
        repository_state=state,
        apply_result=apply_result,
        post_plan=post_plan,
        release_metadata=release,
        output=tmp_path / "hygiene.json",
    )


def test_final_project_hygiene_closes_safe_cleanup_without_deleting_archives(tmp_path: Path):
    payload = _build(tmp_path)
    assert payload["schema"] == "aegisscan.final-project-hygiene.v1"
    assert payload["status"] == "success"
    assert payload["decision"] == "CLEAN"
    assert payload["release_sha"] == SHA
    assert payload["open_pr_count"] == 0
    assert payload["safe_branches_deleted"] == ["codex/merged"]
    assert payload["safe_branch_candidates_after"] == []
    assert payload["retained_branch_categories"]["historical_archive"] == 1
    assert payload["retained_branch_categories"]["safety_backup"] == 1
    assert payload["historical_production_request_reusable"] is False
    assert all(payload["controls"].values())
    assert len(payload["hygiene_sha256"]) == 64


def test_final_hygiene_rejects_open_prs(tmp_path: Path):
    repo_root, state, apply_result, post_plan, release = _fixture(tmp_path)
    value = json.loads(state.read_text())
    value["open_pr_count"] = 1
    state.write_text(json.dumps(value))
    with pytest.raises(FinalHygieneError, match="repository state failed"):
        build_hygiene(
            release_sha=SHA, repository=REPO, repo_root=repo_root,
            repository_state=state, apply_result=apply_result, post_plan=post_plan,
            release_metadata=release, output=tmp_path / "hygiene.json",
        )


def test_final_hygiene_rejects_remaining_safe_candidate(tmp_path: Path):
    repo_root, state, apply_result, post_plan, release = _fixture(tmp_path)
    value = json.loads(post_plan.read_text())
    value["plan"]["delete_candidates"] = ["chatgpt-a/leftover"]
    post_plan.write_text(json.dumps(value))
    with pytest.raises(FinalHygieneError, match="still contains safe deletion candidates"):
        build_hygiene(
            release_sha=SHA, repository=REPO, repo_root=repo_root,
            repository_state=state, apply_result=apply_result, post_plan=post_plan,
            release_metadata=release, output=tmp_path / "hygiene.json",
        )


def test_final_hygiene_rejects_expired_external_request_retained_in_tree(tmp_path: Path):
    repo_root, state, apply_result, post_plan, release = _fixture(tmp_path)
    _write(
        repo_root / ".github/live-acceptance-requests/cloud-providers.json",
        {"schema": "aegisscan.live-acceptance-request.v1"},
    )
    with pytest.raises(FinalHygieneError, match="external live request"):
        build_hygiene(
            release_sha=SHA, repository=REPO, repo_root=repo_root,
            repository_state=state, apply_result=apply_result, post_plan=post_plan,
            release_metadata=release, output=tmp_path / "hygiene.json",
        )


def test_final_hygiene_rejects_production_request_bound_to_final_sha(tmp_path: Path):
    repo_root, state, apply_result, post_plan, release = _fixture(tmp_path)
    path = repo_root / ".github/deployment-requests/internal-production.json"
    value = json.loads(path.read_text())
    value["requested_base_sha"] = SHA
    path.write_text(json.dumps(value))
    with pytest.raises(FinalHygieneError, match="targets the final release SHA"):
        build_hygiene(
            release_sha=SHA, repository=REPO, repo_root=repo_root,
            repository_state=state, apply_result=apply_result, post_plan=post_plan,
            release_metadata=release, output=tmp_path / "hygiene.json",
        )


def test_final_hygiene_workflow_applies_then_replans_fail_closed():
    import yaml
    root = Path(__file__).parents[1]
    path = root / ".github/workflows/final-project-hygiene.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = data["jobs"]["final-project-hygiene"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert data["permissions"]["contents"] == "write"
    names = [step.get("name") for step in job["steps"]]
    apply_index = names.index("Apply live-revalidated safe merged branch cleanup")
    post_index = names.index("Re-plan after cleanup and require zero safe candidates")
    decision_index = names.index("Build final project hygiene decision")
    assert apply_index < post_index < decision_index
    text = path.read_text(encoding="utf-8")
    assert "--include-chatgpt-b" in text
    assert "open_pr_count" in text
    assert "AEGISSCAN_FINAL_HYGIENE=CLEAN" in text
