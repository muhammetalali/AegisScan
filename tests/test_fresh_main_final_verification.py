from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.ci.release1_version import RELEASE_TAG
from scripts.ci.project_completion import build_completion
from release1_evidence_fixture import _build as build_release1_fixture

from scripts.ci.fresh_main_final_verification import (
    FinalVerificationError,
    _require_companion_sha256,
    build_verification,
)

SHA = "a" * 40
REPO = "muhammetalali/AegisScan"


def _write(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _companion(path: Path) -> Path:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    checksum = path.with_suffix(".sha256")
    checksum.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return checksum


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


def _release_fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "release-producer"
    root.mkdir()
    return root


def _fixture(tmp_path: Path):
    state = _write(
        tmp_path / "state.json",
        {"repository": REPO, "default_branch": "main", "main_sha": SHA, "open_pr_count": 0},
    )
    release = _write(
        tmp_path / "release.json",
        {"tagName": RELEASE_TAG, "targetCommitish": SHA, "isDraft": False, "isPrerelease": False},
    )
    tag = _write(
        tmp_path / "tag.json",
        {"ref": f"refs/tags/{RELEASE_TAG}", "object": {"type": "commit", "sha": SHA}},
    )
    runs = {
        "required_ci": _run(tmp_path, "required-ci", "Required CI Governance", ".github/workflows/required-ci-governance.yml", "push", 1),
        "release_closure": _run(tmp_path, "release-run", "Release 1 Closure", ".github/workflows/release1-closure.yml", "workflow_run", 2),
        "provider_closure": _run(tmp_path, "provider-run", "External Provider Acceptance Closure", ".github/workflows/external-provider-acceptance-closure.yml", "workflow_dispatch", 3),
        "performance": _run(tmp_path, "performance-run", "Performance Load Soak Reality", ".github/workflows/performance-load-soak-reality.yml", "workflow_dispatch", 4),
        "hygiene": _run(tmp_path, "hygiene-run", "Final Project Hygiene", ".github/workflows/final-project-hygiene.yml", "workflow_dispatch", 5),
    }
    decisions = {
        "release_closure": _write(
            tmp_path / "release1-closure.json",
            build_release1_fixture(_release_fixture_root(tmp_path)),
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
    checksums = {name: _companion(path) for name, path in decisions.items()}
    return state, release, tag, runs, decisions, checksums


def _build(tmp_path: Path):
    state, release, tag, runs, decisions, checksums = _fixture(tmp_path)
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
        release_closure_sha256=checksums["release_closure"],
        provider_closure=decisions["provider_closure"],
        provider_closure_sha256=checksums["provider_closure"],
        performance_acceptance=decisions["performance"],
        performance_acceptance_sha256=checksums["performance"],
        hygiene=decisions["hygiene"],
        hygiene_sha256=checksums["hygiene"],
        output=tmp_path / "verification.json",
    )


def test_companion_sha256_rejects_mismatched_evidence(tmp_path: Path):
    data = tmp_path / "evidence.json"
    data.write_text('{"ok":true}\n', encoding="utf-8")
    checksum = tmp_path / "evidence.sha256"
    checksum.write_text(f'{"0" * 64}  evidence.json\n', encoding="utf-8")
    with pytest.raises(FinalVerificationError, match="companion SHA256 mismatch"):
        _require_companion_sha256(data, checksum, "fixture evidence")


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
    state, release, tag, runs, decisions, checksums = _fixture(tmp_path)
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
        release_closure_sha256=checksums["release_closure"],
            provider_closure=decisions["provider_closure"],
        provider_closure_sha256=checksums["provider_closure"],
            performance_acceptance=decisions["performance"],
        performance_acceptance_sha256=checksums["performance"], hygiene=decisions["hygiene"],
        hygiene_sha256=checksums["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_final_verification_rejects_non_release_performance_profile(tmp_path: Path):
    state, release, tag, runs, decisions, checksums = _fixture(tmp_path)
    value = json.loads(decisions["performance"].read_text())
    value["profile"] = "ci"
    unsigned = dict(value)
    unsigned.pop("acceptance_sha256", None)
    raw = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    value["acceptance_sha256"] = hashlib.sha256(raw).hexdigest()
    decisions["performance"].write_text(json.dumps(value))
    checksums["performance"] = _companion(decisions["performance"])
    with pytest.raises(FinalVerificationError, match="final release profile"):
        build_verification(
            release_sha=SHA, repository=REPO, repository_state=state,
            release_metadata=release, release_tag_metadata=tag,
            required_ci_run=runs["required_ci"], release_closure_run=runs["release_closure"],
            provider_closure_run=runs["provider_closure"], performance_run=runs["performance"],
            hygiene_run=runs["hygiene"], release_closure=decisions["release_closure"],
        release_closure_sha256=checksums["release_closure"],
            provider_closure=decisions["provider_closure"],
        provider_closure_sha256=checksums["provider_closure"],
            performance_acceptance=decisions["performance"],
        performance_acceptance_sha256=checksums["performance"], hygiene=decisions["hygiene"],
        hygiene_sha256=checksums["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_final_verification_rejects_tag_drift(tmp_path: Path):
    state, release, tag, runs, decisions, checksums = _fixture(tmp_path)
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
        release_closure_sha256=checksums["release_closure"],
            provider_closure=decisions["provider_closure"],
        provider_closure_sha256=checksums["provider_closure"],
            performance_acceptance=decisions["performance"],
        performance_acceptance_sha256=checksums["performance"], hygiene=decisions["hygiene"],
        hygiene_sha256=checksums["hygiene"],
            output=tmp_path / "verification.json",
        )


def test_final_verification_rejects_tampered_embedded_decision_digest(tmp_path: Path):
    state, release, tag, runs, decisions, checksums = _fixture(tmp_path)
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
        release_closure_sha256=checksums["release_closure"],
            provider_closure=decisions["provider_closure"],
        provider_closure_sha256=checksums["provider_closure"],
            performance_acceptance=decisions["performance"],
        performance_acceptance_sha256=checksums["performance"], hygiene=decisions["hygiene"],
        hygiene_sha256=checksums["hygiene"],
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
    assert "release1-closure.sha256" in text
    assert "external-provider-acceptance-closure.sha256" in text
    assert "release-performance-acceptance.sha256" in text
    assert "final-project-hygiene.sha256" in text
    assert "aegisscan-final-project-hygiene-$RELEASE_SHA" in text
    assert "Normalize downloaded final evidence paths fail closed" in text
    assert "expected exactly one regular evidence file" in text
    assert "/tmp/aegis-final/canonical/release/release1-closure.json" in text
    assert "/tmp/aegis-final/canonical/performance/release-performance-acceptance.sha256" in text
    assert "fresh_main_final_verification.py" in text
    assert "AEGISSCAN_FRESH_MAIN_FINAL=VERIFIED" in text

def test_real_release_producer_verifier_and_completion_contract(tmp_path: Path):
    verification = _build(tmp_path)
    assert json.loads((tmp_path / "release1-closure.json").read_text())["release"] == "1"
    assert verification["release"] == 1
    run = _run(
        tmp_path, "fresh-run", "Fresh Main Final Verification",
        ".github/workflows/fresh-main-final-verification.yml", "workflow_dispatch", 6,
    )
    report = tmp_path / "verification.json"
    completion = build_completion(
        release_sha=SHA, repository=REPO,
        repository_state=tmp_path / "state.json",
        release_metadata=tmp_path / "release.json",
        release_tag_metadata=tmp_path / "tag.json",
        verification_run_metadata=run,
        fresh_verification=report,
        fresh_verification_sha256=_companion(report),
        output=tmp_path / "completion.json",
    )
    assert completion["decision"] == "PROJECT_COMPLETE"
    assert completion["release_sha"] == SHA
    assert all(completion["controls"].values())


@pytest.mark.parametrize("release_number", [1, True, 1.0, None, "2", "01"])
def test_final_verification_rejects_noncanonical_release_number(tmp_path, monkeypatch, release_number):
    original = _fixture

    def invalid_fixture(path):
        state, release, tag, runs, decisions, checksums = original(path)
        report = decisions["release_closure"]
        value = json.loads(report.read_text())
        value["release"] = release_number
        value.pop("release_closure_sha256")
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        value["release_closure_sha256"] = hashlib.sha256(raw).hexdigest()
        _write(report, value)
        checksums["release_closure"] = _companion(report)
        return state, release, tag, runs, decisions, checksums

    monkeypatch.setitem(globals(), "_fixture", invalid_fixture)
    with pytest.raises(FinalVerificationError, match="release number mismatch"):
        _build(tmp_path)
