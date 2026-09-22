from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "scripts" / "ci" / "final_red_blue_sre_acceptance.py"
SPEC = importlib.util.spec_from_file_location("aegis_final_red_blue_sre_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RELEASE = "a" * 40


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dimension(root: Path, name: str, *, release_sha: str = RELEASE, status: str = "success") -> Path:
    artifact = root / f"{name}-junit.xml"
    artifact.write_text(f"<testsuite name='{name}' tests='1' failures='0'/>\n", encoding="utf-8")
    payload = {
        "schema": MODULE.DIMENSION_SCHEMA,
        "status": status,
        "dimension": name,
        "release_sha": release_sha,
        "suites": [f"{name}-suite"],
        "artifacts": {artifact.name: _sha(artifact)},
    }
    path = root / f"{name}.json"
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def _root(tmp_path: Path) -> Path:
    for dimension in MODULE.DIMENSIONS:
        _dimension(tmp_path, dimension)
    return tmp_path


def test_build_manifest_accepts_complete_exact_sha_evidence(tmp_path: Path):
    root = _root(tmp_path)
    output = tmp_path / "manifest.json"
    manifest = MODULE.build_manifest(
        release_sha=RELEASE,
        evidence_root=root,
        output=output,
    )
    assert manifest["schema"] == MODULE.MANIFEST_SCHEMA
    assert manifest["status"] == "success"
    assert manifest["decision"] == "ACCEPTED"
    assert manifest["release_sha"] == RELEASE
    assert set(manifest["dimensions"]) == {"red", "blue", "sre"}
    assert all(item["status"] == "success" for item in manifest["dimensions"].values())
    assert all(manifest["controls"].values())
    assert len(manifest["acceptance_sha256"]) == 64
    assert json.loads(output.read_text(encoding="utf-8")) == manifest


def test_manifest_fingerprint_is_deterministic_for_same_evidence(tmp_path: Path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    _root(first_root)
    _root(second_root)

    first = MODULE.build_manifest(
        release_sha=RELEASE,
        evidence_root=first_root,
        output=tmp_path / "first.json",
    )
    second = MODULE.build_manifest(
        release_sha=RELEASE,
        evidence_root=second_root,
        output=tmp_path / "second.json",
    )
    assert first["acceptance_sha256"] == second["acceptance_sha256"]
    assert first["dimensions"] == second["dimensions"]


def test_rejects_dimension_bound_to_another_release(tmp_path: Path):
    _root(tmp_path)
    _dimension(tmp_path, "blue", release_sha="b" * 40)
    with pytest.raises(MODULE.AcceptanceError, match="blue acceptance release SHA mismatch"):
        MODULE.build_manifest(
            release_sha=RELEASE,
            evidence_root=tmp_path,
            output=tmp_path / "manifest.json",
        )


def test_rejects_failed_dimension(tmp_path: Path):
    _root(tmp_path)
    _dimension(tmp_path, "sre", status="failed")
    with pytest.raises(MODULE.AcceptanceError, match="sre acceptance is not successful"):
        MODULE.build_manifest(
            release_sha=RELEASE,
            evidence_root=tmp_path,
            output=tmp_path / "manifest.json",
        )


def test_rejects_tampered_artifact(tmp_path: Path):
    _root(tmp_path)
    artifact = tmp_path / "red-junit.xml"
    artifact.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(MODULE.AcceptanceError, match="artifact digest mismatch"):
        MODULE.build_manifest(
            release_sha=RELEASE,
            evidence_root=tmp_path,
            output=tmp_path / "manifest.json",
        )


def test_rejects_duplicate_or_missing_dimension_evidence(tmp_path: Path):
    _root(tmp_path)
    duplicate_dir = tmp_path / "duplicate"
    duplicate_dir.mkdir()
    (duplicate_dir / "red.json").write_text(
        (tmp_path / "red.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises(MODULE.AcceptanceError, match="exactly one red.json"):
        MODULE.build_manifest(
            release_sha=RELEASE,
            evidence_root=tmp_path,
            output=tmp_path / "manifest.json",
        )

    (duplicate_dir / "red.json").unlink()
    (tmp_path / "blue.json").unlink()
    with pytest.raises(MODULE.AcceptanceError, match="exactly one blue.json"):
        MODULE.build_manifest(
            release_sha=RELEASE,
            evidence_root=tmp_path,
            output=tmp_path / "manifest.json",
        )
