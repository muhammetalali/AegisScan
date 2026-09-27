from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.ci.fresh_main_final_verification import FinalVerificationError, build_verification

SHA = "a" * 40
REPO = "muhammetalali/AegisScan"


def _write(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(tmp_path: Path, key: str, name: str, workflow_path: str, event: str, run_id: int) -> Path:
    return _write(
        tmp_path / f"{key}.json",
        {
            "id": run_id,
            "run_attempt": 1,
            "name": name,
            "path": workflow_path,
            "status": "completed",
            "conclusion": "success",
            "head_sha": SHA,
            "head_branch": "main",
            "event": event,
            "repository": {"full_name": REPO},
        },
    )


def _decision(
    tmp_path: Path,
    name: str,
    schema: str,
    decision: str,
    *,
    digest_field: str,
    extra: dict | None = None,
) -> Path:
    payload = {
        "schema": schema,
        "status": "success",
        "decision": decision,
        "release_sha": SHA,
        "controls": {"one": True, "two": True},
    }
    if extra:
        payload.update(extra)
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    payload[digest_field] = hashlib.sha256(raw).hexdigest()
    return _write(tmp_path / name, payload)


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
    runs = {
        "required_ci": _run(tmp_path, "required-ci", "Required CI Governance", ".github/workflows/required-ci-governance.yml", "push", 1),
        "release_closure": _run(tmp_path, "release-run", "Release 1 Closure", ".github/workflows/release1-closure.yml", "workflow_run", 2),
        "provider_closure": _run(tmp_path, "provider-run", "External Provider Acceptance Closure", ".github/workflows/external-provider-acceptance-closure.yml", "workflow_dispatch", 3),
        "performance": _run(tmp_path, "performance-run", "Performance Load Soak Reality", ".github/workflows/performance-load-soak-reality.yml", "workflow_dispatch", 4),
        "hygiene": _run(tmp_path, "hygiene-run", "Final Project Hygiene", ".github/workflows/final-project-hygiene.yml", "workflow_dispatch", 5),
    }
    decisions = {
        "release_closure": _decision(
            tmp_path, "release1-closure.json", "aegisscan.release1-closure.v1", "RELEASED",
            digest_field="release_closure_sha256",
            extra={"release": 1},
        ),
        "provider_closure": _decision(
            tmp_path, "external-provider-acceptance-closure.json",
            "aegisscan.external-provider-acceptance-closure.v1", "ACCEPTED",
            digest_field="closure_sha256",
        ),
        "performance": _decision(
            tmp_path, "release-performance-acceptance.json",
            "aegisscan.release-performance-acceptance.v1", "ACCEPTED",
            digest_field="acceptance_sha256",
            extra={"profile": "release"},
        ),
        "hygiene": _decision(
            tmp_path, "final-project-hygiene.json",
            "aegisscan.final-project-hygiene.v1", "CLEAN",
            digest_field="hygiene_sha256",
            extra={"open_pr_count": 0, "safe_branch_candidates_after": []},
        ),
    }
    return state, release, tag, runs, decisions


def _build(tmp_path: Path):
    state, release, tag, runs, decisions = _fixture(tmp_path)
    return build_verification(
        release_sha=SHA,
        repository=REPO,
        repository_state=state,
        release_metadata=release,
        release_tag_metadata=tag,
        required_ci_run=runs["required_ci"],
        release_closure_run=runs["release_closure"],
        provider_closure_run=runs["provider_closure"],
        performance_run=runs["performance"],
        hygiene_run=runs["hygiene"],
        release_closure=decisions["release_closure"],
        provider_closure=decisions["provider_closure"],
        performance_acceptance=decisions["performance"],
        hygiene=decisions["hygiene"],
        output=tmp_path / "verification.json",
    )


def test_fresh_main_final_verification_requires_all_exact_sha_planes(tmp_path: Path):
    payload = _build(tmp_path)
    assert payload["schema"] == "aegisscan.fresh-main-final-verification.v1"
    assert payload["status"] == "success"
    assert payload["decision"] == "VERIFIED"
    assert payload["release_sha"] == payload["main_sha"] == SHA
    assert payload["open_pr_count"] == 0
    assert set(payload["workflow_runs"]) == {
        "Required CI Governance",
        "Release 1 Closure",
        "External Provider Acceptance Closure",
        "Performance Load Soak Reality",
        "Final Project Hygiene",
    }
    assert all(payload["controls"].values())
    assert len(payload["verification_sha256"]) == 64


def test_final_verification_rejects_main_sha_drift(tmp_path: Path):
    state, release, tag, runs, decisions = _fixture(tmp_path)
    value = json.loads(state.read_text())
    value["main_sha"] = "f" * 40
    state.write_text(json.dumps(value))
    with pytest.raises(FinalVerificationError, match="zero-drift"):
        build_verification(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            required_ci_run=runs["required_ci"], release_closure_run=runs["release_closure"],
            provider_closure_run=runs["provider_closure"], performance_run=runs["performance"],
            hygiene_run=runs["hygiene"], release_closure=decisions["release_closure"],
            provider_closure=decisions["provider_closure"],
            performance_acceptance=decisions["performance"], hygiene=decisions["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_final_verification_rejects_non_release_performance_profile(tmp_path: Path):
    state, release, tag, runs, decisions = _fixture(tmp_path)
    value = json.loads(decisions["performance"].read_text())
    value["profile"] = "ci"
    decisions["performance"].write_text(json.dumps(value))
    with pytest.raises(FinalVerificationError, match="final release profile"):
        build_verification(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            required_ci_run=runs["required_ci"], release_closure_run=runs["release_closure"],
            provider_closure_run=runs["provider_closure"], performance_run=runs["performance"],
            hygiene_run=runs["hygiene"], release_closure=decisions["release_closure"],
            provider_closure=decisions["provider_closure"],
            performance_acceptance=decisions["performance"], hygiene=decisions["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_final_verification_rejects_tag_drift(tmp_path: Path):
    state, release, tag, runs, decisions = _fixture(tmp_path)
    value = json.loads(tag.read_text())
    value["object"]["sha"] = "e" * 40
    tag.write_text(json.dumps(value))
    with pytest.raises(FinalVerificationError, match="tag does not point"):
        build_verification(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            required_ci_run=runs["required_ci"], release_closure_run=runs["release_closure"],
            provider_closure_run=runs["provider_closure"], performance_run=runs["performance"],
            hygiene_run=runs["hygiene"], release_closure=decisions["release_closure"],
            provider_closure=decisions["provider_closure"],
            performance_acceptance=decisions["performance"], hygiene=decisions["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_final_verification_rejects_tampered_embedded_decision_digest(tmp_path: Path):
    state, release, tag, runs, decisions = _fixture(tmp_path)
    value = json.loads(decisions["provider_closure"].read_text())
    value["controls"]["tampered"] = True
    decisions["provider_closure"].write_text(json.dumps(value))
    with pytest.raises(FinalVerificationError, match="embedded digest mismatch"):
        build_verification(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            required_ci_run=runs["required_ci"], release_closure_run=runs["release_closure"],
            provider_closure_run=runs["provider_closure"], performance_run=runs["performance"],
            hygiene_run=runs["hygiene"], release_closure=decisions["release_closure"],
            provider_closure=decisions["provider_closure"],
            performance_acceptance=decisions["performance"], hygiene=decisions["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_fresh_main_workflow_downloads_all_final_decision_artifacts():
    import yaml
    root = Path(__file__).parents[1]
    path = root / ".github/workflows/fresh-main-final-verification.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["fresh-main-final-verification"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    text = path.read_text(encoding="utf-8")
    assert "aegisscan-release1-closure-$RELEASE_SHA" in text
    assert "aegisscan-external-provider-closure-$RELEASE_SHA" in text
    assert "release-performance-acceptance-$RELEASE_SHA" in text
    assert "aegisscan-final-project-hygiene-$RELEASE_SHA" in text
    assert "fresh_main_final_verification.py" in text
    assert "AEGISSCAN_FRESH_MAIN_FINAL=VERIFIED" in text
