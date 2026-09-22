from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "release1_closure.py"
SPEC = importlib.util.spec_from_file_location("release1_closure", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

SHA = "a" * 40
REPO = "example/aegisscan"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _run_payload(key: str, *, release_sha: str = SHA) -> dict:
    name, path, event = MODULE.EXPECTED_RUNS[key]
    return {
        "id": 1000 + list(MODULE.EXPECTED_RUNS).index(key),
        "name": name,
        "path": path,
        "event": event,
        "status": "completed",
        "conclusion": "success",
        "head_sha": release_sha,
        "head_branch": "main",
        "html_url": f"https://github.com/{REPO}/actions/runs/1",
        "repository": {"full_name": REPO},
    }


def _fixture(tmp_path: Path, *, release_sha: str = SHA) -> dict:
    metadata = tmp_path / "metadata"
    for key in MODULE.EXPECTED_RUNS:
        _write_json(metadata / f"{key}.json", _run_payload(key, release_sha=release_sha))

    final_governance = tmp_path / "final-governance"
    governance_payload = {
        "schema": "aegisscan.final-governance-closure.v1",
        "status": "success",
        "decision": "APPROVED",
        "release_sha": release_sha,
        "controls": {"governance": True},
        "dimensions": {"risk_acceptance": {"status": "success"}},
        "governance_sha256": "b" * 64,
    }
    _write_json(final_governance / "final-governance-closure.json", governance_payload)

    final_acceptance = tmp_path / "final-acceptance"
    acceptance_payload = {
        "schema": "aegisscan.final-red-blue-sre-acceptance.v1",
        "status": "success",
        "decision": "ACCEPTED",
        "release_sha": release_sha,
        "dimensions": {
            "red": {"status": "success"},
            "blue": {"status": "success"},
            "sre": {"status": "success"},
        },
        "controls": {"objective_based_acceptance": True},
        "acceptance_sha256": "c" * 64,
    }
    _write_json(final_acceptance / "final-red-blue-sre-acceptance.json", acceptance_payload)

    production_governance = tmp_path / "production-governance"
    production_payload = {
        "schema": "aegisscan.production-governance-decision.v2",
        "status": "success",
        "decision": "APPROVED",
        "deployment_mode": "internal",
        "release_sha": release_sha,
        "internal_origin": "https://aegis.internal.example",
        "decided_at": "2026-09-22T16:00:00Z",
        "controls": {
            "exact_release_deployed": True,
            "remote_encrypted_backup": True,
            "version_pinned_restore": True,
            "disposable_database_restore": True,
            "external_alert_delivery": True,
            "supply_chain_provenance": True,
            "cyclonedx_sbom": True,
        },
    }
    _write_json(production_governance / "decision.json", production_payload)

    supply_chain = tmp_path / "supply-chain"
    for component in MODULE.COMPONENTS:
        provenance = {
            "invocation": {
                "configSource": {
                    "digest": {"sha1": release_sha},
                    "entryPoint": ".github/workflows/supply-chain-release.yml",
                },
                "parameters": {"image": f"ghcr.io/example/aegisscan-{component}"},
            },
            "materials": [{"digest": {"sha1": release_sha}}],
        }
        _write_json(supply_chain / f"{component}.provenance.json", provenance)
        _write_json(supply_chain / f"{component}.cdx.json", {"bomFormat": "CycloneDX"})

    state = tmp_path / "repository-state.json"
    _write_json(state, {
        "default_branch": "main",
        "default_branch_sha": release_sha,
        "open_pull_requests": 0,
        "release_pr_number": 213,
        "release_pr_merged": True,
        "release_head_ref": "chatgpt-a/release-1-closure-20260922",
        "release_head_branch_absent": True,
    })

    return {
        "release_sha": release_sha,
        "repository": REPO,
        "metadata_root": metadata,
        "final_governance_root": final_governance,
        "final_acceptance_root": final_acceptance,
        "production_governance_root": production_governance,
        "supply_chain_root": supply_chain,
        "repository_state": state,
        "output": tmp_path / "release1.json",
    }


def test_release1_manifest_closes_exact_sha_with_all_evidence(tmp_path: Path):
    args = _fixture(tmp_path)
    payload = MODULE.build_release_manifest(**args)

    assert payload["decision"] == "RELEASED"
    assert payload["release"] == "1"
    assert payload["release_sha"] == SHA
    assert all(payload["controls"].values())
    assert payload["repository_state"]["open_pull_requests"] == 0
    assert set(payload["workflow_runs"]) == set(MODULE.EXPECTED_RUNS)
    assert set(payload["evidence"]["supply_chain"]) == set(MODULE.COMPONENTS)
    assert len(payload["release_manifest_sha256"]) == 64
    assert json.loads(args["output"].read_text(encoding="utf-8")) == payload


def test_release1_rejects_cross_sha_workflow_evidence(tmp_path: Path):
    args = _fixture(tmp_path)
    path = args["metadata_root"] / "required_ci.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["head_sha"] = "d" * 40
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseClosureError, match="exact-SHA"):
        MODULE.build_release_manifest(**args)


def test_release1_rejects_open_pull_requests(tmp_path: Path):
    args = _fixture(tmp_path)
    state = json.loads(args["repository_state"].read_text(encoding="utf-8"))
    state["open_pull_requests"] = 1
    _write_json(args["repository_state"], state)

    with pytest.raises(MODULE.ReleaseClosureError, match="zero open pull"):
        MODULE.build_release_manifest(**args)


def test_release1_rejects_release_branch_still_present(tmp_path: Path):
    args = _fixture(tmp_path)
    state = json.loads(args["repository_state"].read_text(encoding="utf-8"))
    state["release_head_branch_absent"] = False
    _write_json(args["repository_state"], state)

    with pytest.raises(MODULE.ReleaseClosureError, match="has not been removed"):
        MODULE.build_release_manifest(**args)


def test_release1_rejects_supply_chain_cross_sha(tmp_path: Path):
    args = _fixture(tmp_path)
    provenance = args["supply_chain_root"] / "django.provenance.json"
    payload = json.loads(provenance.read_text(encoding="utf-8"))
    payload["materials"][0]["digest"] = {"sha1": "e" * 40}
    _write_json(provenance, payload)

    with pytest.raises(MODULE.ReleaseClosureError, match="provenance"):
        MODULE.build_release_manifest(**args)


def test_release1_rejects_tampered_production_decision(tmp_path: Path):
    args = _fixture(tmp_path)
    path = args["production_governance_root"] / "decision.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["controls"]["version_pinned_restore"] = False
    _write_json(path, payload)

    with pytest.raises(MODULE.ReleaseClosureError, match="production governance"):
        MODULE.build_release_manifest(**args)


@pytest.mark.parametrize("release_sha", ["", "abc", "A" * 40, "g" * 40])
def test_release1_rejects_invalid_sha(tmp_path: Path, release_sha: str):
    args = _fixture(tmp_path)
    args["release_sha"] = release_sha
    with pytest.raises(MODULE.ReleaseClosureError, match="40 lowercase hexadecimal"):
        MODULE.build_release_manifest(**args)
