from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.external_provider_acceptance_closure import (
    CLOUD_WORKFLOW,
    IDENTITY_WORKFLOW,
    ProviderClosureError,
    build_closure,
)

SHA = "a" * 40
REPO = "muhammetalali/AegisScan"


def _write(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _run(name: str, path: str, run_id: int, steps: list[str]) -> dict:
    return {
        "id": run_id,
        "run_attempt": 1,
        "name": name,
        "path": path,
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "updated_at": "2026-09-27T15:00:00Z",
        "repository": {"full_name": REPO},
        "jobs": [{
            "id": run_id * 10,
            "run_id": run_id,
            "run_attempt": 1,
            "head_sha": SHA,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {"name": step, "status": "completed", "conclusion": "success"}
                for step in steps
            ],
        }],
    }


def _fixture(tmp_path: Path):
    cloud_root = tmp_path / "cloud"
    identity_root = tmp_path / "identity"
    cloud_steps = [
        "Require at least one complete live-provider binding",
        "Wait for exact-SHA Required CI Governance",
        "Execute and validate configured live providers",
        "Prove artifacts contain no raw credential material",
    ]
    identity_steps = [
        "Require at least one complete external identity binding",
        "Wait for exact-SHA Required CI Governance",
        "Execute real read-only external identity validation",
        "Prove secret-safe immutable identity evidence",
    ]
    cloud_run = _write(
        tmp_path / "cloud-run.json",
        _run(CLOUD_WORKFLOW[0], CLOUD_WORKFLOW[1], 101, cloud_steps),
    )
    identity_run = _write(
        tmp_path / "identity-run.json",
        _run(IDENTITY_WORKFLOW[0], IDENTITY_WORKFLOW[1], 102, identity_steps),
    )
    _write(
        cloud_root / "aws-proof.json",
        {
            "schema": "aegis.cloud-live-provider-proof.v1",
            "source_schema": "aegis.cloud-security.v1",
            "source_sha": SHA,
            "provider": "aws",
            "target": "aws://123456789012/us-east-1",
            "identity_verified": True,
            "read_only": True,
            "ambient_credentials_used": False,
            "credential_source": "vault-materialized-file",
            "finding_count": 2,
            "coverage_gap_count": 0,
            "result_sha256": "b" * 64,
        },
    )
    _write(
        identity_root / "proof.json",
        {
            "schema": "aegis.external-identity-live-proof.v1",
            "status": "success",
            "source_sha": SHA,
            "read_only": True,
            "ambient_credentials_used": False,
            "configured_types": ["oidc"],
            "oidc": {
                "signing_key_count": 2,
                "pkce_s256": True,
                "authorization_code_flow": True,
            },
            "completed_at": "2026-09-27T15:01:00Z",
        },
    )
    return cloud_run, identity_run, cloud_root, identity_root


def _build(tmp_path: Path):
    cloud_run, identity_run, cloud_root, identity_root = _fixture(tmp_path)
    return build_closure(
        release_sha=SHA,
        repository=REPO,
        cloud_run_metadata=cloud_run,
        identity_run_metadata=identity_run,
        cloud_evidence_root=cloud_root,
        identity_evidence_root=identity_root,
        output=tmp_path / "closure.json",
    )


def test_provider_closure_requires_real_exact_sha_evidence(tmp_path: Path):
    payload = _build(tmp_path)
    assert payload["schema"] == "aegisscan.external-provider-acceptance-closure.v1"
    assert payload["status"] == "success"
    assert payload["decision"] == "ACCEPTED"
    assert payload["release_sha"] == SHA
    assert set(payload["cloud"]["providers"]) == {"aws"}
    assert payload["external_identity"]["configured_types"] == ["oidc"]
    assert all(payload["controls"].values())
    assert len(payload["closure_sha256"]) == 64


def test_provider_closure_rejects_cleanup_only_green_cloud_run(tmp_path: Path):
    cloud_run, identity_run, cloud_root, identity_root = _fixture(tmp_path)
    run = json.loads(cloud_run.read_text())
    for step in run["jobs"][0]["steps"]:
        if step["name"] == "Execute and validate configured live providers":
            step["conclusion"] = "skipped"
    cloud_run.write_text(json.dumps(run))
    with pytest.raises(ProviderClosureError, match="did not execute"):
        build_closure(
            release_sha=SHA,
            repository=REPO,
            cloud_run_metadata=cloud_run,
            identity_run_metadata=identity_run,
            cloud_evidence_root=cloud_root,
            identity_evidence_root=identity_root,
            output=tmp_path / "closure.json",
        )


def test_provider_closure_rejects_cross_sha_artifact(tmp_path: Path):
    cloud_run, identity_run, cloud_root, identity_root = _fixture(tmp_path)
    proof_path = cloud_root / "aws-proof.json"
    proof = json.loads(proof_path.read_text())
    proof["source_sha"] = "f" * 40
    proof_path.write_text(json.dumps(proof))
    with pytest.raises(ProviderClosureError, match="source_sha"):
        build_closure(
            release_sha=SHA,
            repository=REPO,
            cloud_run_metadata=cloud_run,
            identity_run_metadata=identity_run,
            cloud_evidence_root=cloud_root,
            identity_evidence_root=identity_root,
            output=tmp_path / "closure.json",
        )


def test_provider_closure_rejects_empty_identity_provider_set(tmp_path: Path):
    cloud_run, identity_run, cloud_root, identity_root = _fixture(tmp_path)
    proof_path = identity_root / "proof.json"
    proof = json.loads(proof_path.read_text())
    proof["configured_types"] = []
    proof_path.write_text(json.dumps(proof))
    with pytest.raises(ProviderClosureError, match="authoritative checks"):
        build_closure(
            release_sha=SHA,
            repository=REPO,
            cloud_run_metadata=cloud_run,
            identity_run_metadata=identity_run,
            cloud_evidence_root=cloud_root,
            identity_evidence_root=identity_root,
            output=tmp_path / "closure.json",
        )


def test_provider_closure_workflow_requires_published_release_and_exact_artifacts():
    import yaml
    root = Path(__file__).parents[1]
    workflow = yaml.safe_load(
        (root / ".github/workflows/external-provider-acceptance-closure.yml").read_text()
    )
    job = workflow["jobs"]["provider-closure"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    text = (root / ".github/workflows/external-provider-acceptance-closure.yml").read_text()
    assert "gh release view v1.0.0" in text
    assert 'release[\'targetCommitish\'] == os.environ[\'RELEASE_SHA\']' in text
    assert "cloud-live-provider-proof-$RELEASE_SHA" in text
    assert "external-identity-live-proof-$RELEASE_SHA" in text
    assert "external_provider_acceptance_closure.py" in text
    assert "AEGISSCAN_EXTERNAL_PROVIDERS=ACCEPTED" in text
