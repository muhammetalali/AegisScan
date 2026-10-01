from __future__ import annotations

import json
from pathlib import Path

from scripts.ci.release1_closure import REQUIRED_RUNS, build_manifest

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
    job_name = {
        "Internal Production Deploy and Acceptance": "deploy-and-accept",
        "Production Resilience Acceptance": "resilience-acceptance",
        "Final Internal Production Governance": "final-governance",
    }.get(name, "contract")
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
        "jobs": [{
            "id": run_id * 10, "run_id": run_id, "run_attempt": 1,
            "head_sha": SHA, "name": job_name, "status": "completed", "conclusion": "success",
            "steps": [{"name": "accept", "status": "completed", "conclusion": "success"}],
        }],
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
        _write(evidence / f"{component}.cdx.json", {"bomFormat": "CycloneDX", "components": [{"name": component}]})
        supply_run_id = list(REQUIRED_RUNS).index("Supply Chain Release") + 1
        _write(evidence / f"{component}.provenance.json", {
            "builder": {"id": f"https://github.com/{REPO}/actions/runs/{supply_run_id}"},
            "invocation": {"configSource": {
                "uri": f"git+https://github.com/{REPO}@refs/heads/main",
                "digest": {"sha1": SHA}, "entryPoint": ".github/workflows/supply-chain-release.yml",
            }},
        })

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



