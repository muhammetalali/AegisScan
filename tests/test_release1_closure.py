from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.release1_closure import (
    REQUIRED_RUNS,
    ReleaseClosureError,
    build_manifest,
)

SHA = "a" * 40
REPO = "muhammetalali/AegisScan"


def _write(path: Path, payload) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, (dict, list)):
        path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        path.write_text(str(payload), encoding="utf-8")
    return path


def _run(name: str, path: str, events: set[str], run_id: int) -> dict:
    event = sorted(events)[0]
    return {
        "id": run_id,
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA,
        "head_branch": "main",
        "path": path,
        "event": event,
        "run_attempt": 1,
        "updated_at": "2026-09-22T16:00:00Z",
        "repository": {"full_name": REPO},
    }


def _fixture(tmp_path: Path):
    metadata = tmp_path / "metadata"
    evidence = tmp_path / "evidence"
    metadata.mkdir()
    evidence.mkdir()

    for index, (name, (path, events)) in enumerate(REQUIRED_RUNS.items(), start=1):
        _write(metadata / f"run-{index}.json", _run(name, path, events, index))

    _write(
        evidence / "final-red-blue-sre-acceptance.json",
        {
            "schema": "aegisscan.final-red-blue-sre-acceptance.v1",
            "status": "success",
            "decision": "ACCEPTED",
            "release_sha": SHA,
            "acceptance_sha256": "b" * 64,
        },
    )
    _write(
        evidence / "final-governance-closure.json",
        {
            "schema": "aegisscan.final-governance-closure.v1",
            "status": "success",
            "decision": "APPROVED",
            "release_sha": SHA,
            "governance_sha256": "c" * 64,
        },
    )
    _write(
        evidence / "decision.json",
        {
            "schema": "aegisscan.production-governance-decision.v2",
            "status": "success",
            "decision": "APPROVED",
            "release_sha": SHA,
            "deployment_mode": "internal",
            "internal_origin": "https://aegisscan.internal.example",
        },
    )
    for component in ("django", "fastapi", "frontend"):
        _write(evidence / f"{component}.cdx.json", {"bomFormat": "CycloneDX", "component": component})
        _write(evidence / f"{component}.provenance.json", {"component": component, "release_sha": SHA})

    repository_state = _write(
        tmp_path / "repository-state.json",
        {
            "repository": REPO,
            "default_branch": "main",
            "main_sha": SHA,
            "open_pr_count": 0,
        },
    )
    branch_hygiene = _write(
        tmp_path / "branch-hygiene.json",
        {
            "plan": {
                "schema": "aegis.branch-hygiene-plan.v1",
                "repository": REPO,
                "default_branch": "main",
                "default_sha": SHA,
                "open_pr_heads": [],
                "inventory": [{"name": "main", "sha": SHA}],
                "delete_candidates": ["chatgpt-a/old-merged"],
            },
            "deleted": [{"name": "chatgpt-a/old-merged", "sha": "d" * 40}],
        },
    )
    return metadata, evidence, repository_state, branch_hygiene


def _build(tmp_path: Path):
    metadata, evidence, repository_state, branch_hygiene = _fixture(tmp_path)
    return build_manifest(
        release_sha=SHA,
        repository=REPO,
        metadata_root=metadata,
        evidence_root=evidence,
        repository_state=repository_state,
        branch_hygiene=branch_hygiene,
        output=tmp_path / "release1.json",
    )


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
