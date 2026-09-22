from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "final_governance_closure.py"
SPEC = importlib.util.spec_from_file_location("final_governance_closure", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

SHA = "a" * 40


def _write_dimension(root: Path, dimension: str, release_sha: str = SHA) -> None:
    artifact = root / f"{dimension}-junit.xml"
    artifact.write_text(f"<testsuite name='{dimension}' tests='1' failures='0'/>\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    payload = {
        "schema": MODULE.DIMENSION_SCHEMA,
        "status": "success",
        "dimension": dimension,
        "release_sha": release_sha,
        "suites": [f"{dimension}-suite"],
        "artifacts": {artifact.name: digest},
    }
    (root / f"{dimension}.json").write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _evidence_root(tmp_path: Path) -> Path:
    root = tmp_path / "governance"
    root.mkdir()
    for dimension in MODULE.DIMENSIONS:
        _write_dimension(root, dimension)
    return root


def test_build_manifest_binds_all_governance_dimensions_to_exact_sha(tmp_path: Path):
    root = _evidence_root(tmp_path)
    output = tmp_path / "final-governance.json"
    payload = MODULE.build_manifest(release_sha=SHA, evidence_root=root, output=output)

    assert payload["status"] == "success"
    assert payload["decision"] == "APPROVED"
    assert payload["release_sha"] == SHA
    assert set(payload["dimensions"]) == set(MODULE.DIMENSIONS)
    assert all(payload["controls"].values())
    assert len(payload["governance_sha256"]) == 64
    assert json.loads(output.read_text(encoding="utf-8")) == payload


def test_build_manifest_fails_closed_on_artifact_tamper(tmp_path: Path):
    root = _evidence_root(tmp_path)
    (root / "audit_integrity-junit.xml").write_text("tampered\n", encoding="utf-8")

    with pytest.raises(MODULE.GovernanceClosureError, match="digest mismatch"):
        MODULE.build_manifest(
            release_sha=SHA,
            evidence_root=root,
            output=tmp_path / "out.json",
        )


def test_build_manifest_fails_closed_on_cross_sha_evidence(tmp_path: Path):
    root = _evidence_root(tmp_path)
    _write_dimension(root, "risk_acceptance", release_sha="b" * 40)

    with pytest.raises(MODULE.GovernanceClosureError, match="release SHA mismatch"):
        MODULE.build_manifest(
            release_sha=SHA,
            evidence_root=root,
            output=tmp_path / "out.json",
        )


@pytest.mark.parametrize("release_sha", ["", "abc", "A" * 40, "g" * 40])
def test_build_manifest_rejects_invalid_release_sha(tmp_path: Path, release_sha: str):
    root = _evidence_root(tmp_path)
    with pytest.raises(MODULE.GovernanceClosureError, match="40 lowercase hexadecimal"):
        MODULE.build_manifest(
            release_sha=release_sha,
            evidence_root=root,
            output=tmp_path / "out.json",
        )
