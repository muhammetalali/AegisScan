"""Synthetic BApp archive negative controls. Never downloads, loads or executes BApps."""
from __future__ import annotations

import hashlib
import io
import json
import stat
import sys
import warnings
import zipfile
from pathlib import Path

import pytest

from scripts.ci.bapp_supplier_preflight import BAppPreflightError, audit, main


MANIFEST = (
    b"Uuid: 9952290f04ed4f628e624d0aa9dccebc\n"
    b"ExtensionType: 1\n"
    b"Name: MCP Server\n"
    b"RepoName: mcp-server\n"
    b"ScreenVersion: 1.4.0\n"
    b"SerialVersion: 12\n"
    b"EntryPoint: burp-mcp-all.jar\n"
)
JAR_MANIFEST = (
    b"Manifest-Version: 1.0\n"
    b"Implementation-Title: burp-mcp\n"
    b"Implementation-Version: 1.4.0\n"
    b"Implementation-Vendor: PortSwigger\n"
    b"Built-Date: 2026-11-05T12:00:00Z\n"
)
SIGNATURE = b"S" * 128
UUID = "9952290f04ed4f628e624d0aa9dccebc"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _archive(tmp_path: Path, *, outer: dict[str, bytes] | None = None,
             jar_files: dict[str, bytes] | None = None,
             duplicate: str = "", symlink: str = "") -> tuple[Path, Path]:
    jar_buffer = io.BytesIO()
    with zipfile.ZipFile(jar_buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for key, value in (jar_files or {"META-INF/MANIFEST.MF": JAR_MANIFEST}).items():
            z.writestr(key, value)
    files = outer or {
        "burp-mcp-all.jar": jar_buffer.getvalue(),
        "BappManifest.bmf": MANIFEST,
        "BappDescription.html": b"<p>synthetic fixture</p>",
        "BappSignature.sig": SIGNATURE,
    }
    archive = tmp_path / "fixture.bapp"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for name, raw in files.items():
            if name == symlink:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, raw)
            else:
                z.writestr(name, raw)
        if duplicate:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                z.writestr(duplicate, files[duplicate])
    source = tmp_path / "source.bmf"
    source.write_bytes(MANIFEST)
    return archive, source


def _audit(archive: Path, source: Path, **overrides):
    kwargs = {
        "expected_archive_sha256": _sha(archive.read_bytes()),
        "expected_signature_sha256": _sha(SIGNATURE),
        "source_manifest": source,
        "expected_uuid": UUID,
        "expected_version": "1.4.0",
        "expected_serial": 12,
    }
    kwargs.update(overrides)
    return audit(archive, **kwargs)


def test_valid_synthetic_archive_is_integrity_only_never_trusted(tmp_path):
    archive, source = _archive(tmp_path)
    result = _audit(archive, source)
    assert result["checks"]["bounded_structure_and_crc"] is True
    assert result["checks"]["manifest_byte_matches_pinned_source"] is True
    assert result["checks"]["cryptographic_publisher_signature_verified"] is False
    assert result["checks"]["supplier_sbom_verified"] is False
    assert result["checks"]["supplier_provenance_verified"] is False
    assert result["checks"]["reproducible_build_independently_verified"] is False
    assert result["governance"]["admission"] == "BLOCKED"
    assert result["governance"]["provider_trusted"] is False
    assert result["governance"]["production_installed"] is False


@pytest.mark.parametrize("bad_digest", ["0" * 64, "BAD", "x" * 64])
def test_archive_digest_is_strictly_pinned(tmp_path, bad_digest):
    archive, source = _archive(tmp_path)
    with pytest.raises(BAppPreflightError, match="archive_digest_mismatch|invalid_digest_pin"):
        _audit(archive, source, expected_archive_sha256=bad_digest)


def test_source_manifest_byte_drift_denies(tmp_path):
    archive, source = _archive(tmp_path)
    source.write_bytes(MANIFEST.replace(b"ScreenVersion: 1.4.0", b"ScreenVersion: 1.4.1"))
    with pytest.raises(BAppPreflightError, match="source_manifest_mismatch"):
        _audit(archive, source)


def test_signature_blob_digest_mismatch_denies(tmp_path):
    archive, source = _archive(tmp_path)
    with pytest.raises(BAppPreflightError, match="signature_digest_mismatch"):
        _audit(archive, source, expected_signature_sha256=_sha(b"other"))


def test_missing_signature_or_unexpected_zip_entry_denies(tmp_path):
    archive, source = _archive(tmp_path)
    with zipfile.ZipFile(archive) as z:
        files = {n: z.read(n) for n in z.namelist() if n != "BappSignature.sig"}
    archive, source = _archive(tmp_path, outer=files)
    with pytest.raises(BAppPreflightError, match="entry_count_limit"):
        _audit(archive, source)


def test_outer_path_traversal_denied_without_extracting(tmp_path):
    archive, source = _archive(tmp_path)
    with zipfile.ZipFile(archive) as z:
        files = {n: z.read(n) for n in z.namelist()}
    files["../escape.jar"] = files.pop("burp-mcp-all.jar")
    archive, source = _archive(tmp_path, outer=files)
    with pytest.raises(BAppPreflightError, match="unsafe_archive_entry"):
        _audit(archive, source)
    assert not (tmp_path.parent / "escape.jar").exists()


def test_duplicate_entry_and_symlink_are_denied(tmp_path):
    archive, source = _archive(tmp_path, duplicate="BappManifest.bmf")
    with pytest.raises(BAppPreflightError, match="entry_count_limit|duplicate_archive_entry"):
        _audit(archive, source)
    archive, source = _archive(tmp_path, symlink="BappSignature.sig")
    with pytest.raises(BAppPreflightError, match="non_regular_archive_entry"):
        _audit(archive, source)


def test_jar_zip_slip_and_wrong_implementation_version_denied(tmp_path):
    archive, source = _archive(tmp_path, jar_files={
        "META-INF/MANIFEST.MF": JAR_MANIFEST,
        "../bad.class": b"class",
    })
    with pytest.raises(BAppPreflightError, match="unsafe_archive_entry"):
        _audit(archive, source)
    archive, source = _archive(tmp_path, jar_files={
        "META-INF/MANIFEST.MF": JAR_MANIFEST.replace(b"1.4.0", b"1.3.0"),
    })
    with pytest.raises(BAppPreflightError, match="jar_manifest_version_mismatch"):
        _audit(archive, source)


def test_zip_bomb_ratio_is_rejected_pre_decompression(tmp_path):
    archive, source = _archive(tmp_path, jar_files={
        "META-INF/MANIFEST.MF": JAR_MANIFEST,
        "bomb.class": b"\x00" * (5 * 1024 * 1024),
    })
    with pytest.raises(BAppPreflightError, match="expansion_ratio_limit"):
        _audit(archive, source)


def test_mismatched_release_identity_is_denied(tmp_path):
    archive, source = _archive(tmp_path)
    with pytest.raises(BAppPreflightError, match="vendor_manifest_identity_mismatch"):
        _audit(archive, source, expected_serial=10)


def test_existing_output_never_overwritten_or_escalated_to_approval(tmp_path, monkeypatch):
    archive, source = _archive(tmp_path)
    output = tmp_path / "receipt.json"
    output.write_text('{"previous":"not-overwritten"}\n')
    monkeypatch.setattr(sys, "argv", [
        "bapp_supplier_preflight.py", "--archive", str(archive),
        "--expected-archive-sha256", _sha(archive.read_bytes()),
        "--expected-signature-sha256", _sha(SIGNATURE),
        "--source-manifest", str(source), "--expected-uuid", UUID,
        "--expected-version", "1.4.0", "--expected-serial", "12",
        "--output", str(output),
    ])
    assert main() == 1
    assert json.loads(output.read_text()) == {"previous": "not-overwritten"}
    output.unlink()
    assert main() == 0
    assert json.loads(output.read_text())["governance"]["admission"] == "BLOCKED"
    assert output.stat().st_mode & 0o777 == 0o600


def test_supply_chain_ci_runs_new_fail_closed_controls():
    root = Path(__file__).parents[1]
    text = (root / ".github/workflows/supply-chain-release.yml").read_text()
    assert "tests/test_bapp_supplier_preflight.py" in text
    assert "scripts/ci/bapp_supplier_preflight.py" in text
