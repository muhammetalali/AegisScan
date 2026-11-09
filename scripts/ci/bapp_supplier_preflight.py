#!/usr/bin/env python3
"""Bounded offline integrity preflight for the *unexecuted* PortSwigger MCP BApp.

This is NOT supplier signature verification or provider approval. An official-
looking ZIP or a matching locally supplied SHA-256 is never a trust anchor.
The decision remains BLOCKED until an independently authenticated publisher
signature, vendor SBOM/provenance and reproducibility have been reviewed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

EXPECTED_FILES = frozenset({
    "burp-mcp-all.jar", "BappManifest.bmf",
    "BappDescription.html", "BappSignature.sig",
})
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 70 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_RATIO = 100
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class BAppPreflightError(ValueError):
    """Fail-closed archive and independent-source integrity error."""


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest_file(path: Path) -> str:
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            total += len(block)
            if total > MAX_ARCHIVE_BYTES:
                raise BAppPreflightError("archive_size_limit")
            h.update(block)
    return h.hexdigest()


def _safe_members(z: zipfile.ZipFile, *, jar: bool) -> dict[str, zipfile.ZipInfo]:
    entries = z.infolist()
    if not entries or len(entries) > (MAX_ENTRIES if jar else len(EXPECTED_FILES)) or (not jar and len(entries) != len(EXPECTED_FILES)):
        raise BAppPreflightError("entry_count_limit")
    seen: dict[str, zipfile.ZipInfo] = {}
    inflated = 0
    for item in entries:
        name = item.filename
        parts = PurePosixPath(name).parts
        if (
            not name or name.startswith("/") or "\\" in name or "\x00" in name
            or any(part in {".", ".."} for part in name.rstrip("/").split("/"))
            or not parts or item.flag_bits & 1
        ):
            raise BAppPreflightError("unsafe_archive_entry")
        mode = item.external_attr >> 16
        if mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise BAppPreflightError("non_regular_archive_entry")
        if item.file_size > MAX_MEMBER_BYTES or item.compress_size > MAX_ARCHIVE_BYTES:
            raise BAppPreflightError("entry_size_limit")
        if item.file_size > max(1, item.compress_size) * MAX_RATIO:
            raise BAppPreflightError("expansion_ratio_limit")
        inflated += item.file_size
        if inflated > MAX_UNCOMPRESSED_BYTES:
            raise BAppPreflightError("inflated_size_limit")
        if name in seen:
            raise BAppPreflightError("duplicate_archive_entry")
        seen[name] = item
    if not jar and set(seen) != EXPECTED_FILES:
        raise BAppPreflightError("unexpected_bapp_members")
    return seen


def _manifest(raw: bytes) -> dict[str, str]:
    if len(raw) > 8192:
        raise BAppPreflightError("manifest_size_limit")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise BAppPreflightError("manifest_invalid_utf8") from exc
    props: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep or not key or key.strip() != key or key in props:
            raise BAppPreflightError("manifest_invalid_structure")
        props[key] = value.strip()
    return props


def audit(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_signature_sha256: str,
    source_manifest: Path,
    expected_uuid: str,
    expected_version: str,
    expected_serial: int,
) -> dict:
    """Inspect bytes only: NEVER execute JARs, initialize Burp or access a target."""
    for value in (expected_archive_sha256, expected_signature_sha256):
        if not HEX_SHA256.fullmatch(value):
            raise BAppPreflightError("invalid_digest_pin")
    if not (archive.is_file() and not archive.is_symlink()
            and source_manifest.is_file() and not source_manifest.is_symlink()):
        raise BAppPreflightError("input_file_invalid")
    archive_digest = _digest_file(archive)
    if archive_digest != expected_archive_sha256:
        raise BAppPreflightError("archive_digest_mismatch")
    try:
        with archive.open("rb") as f:
            if f.read(4) != b"PK\x03\x04":
                raise BAppPreflightError("invalid_zip_prefix")
        with zipfile.ZipFile(archive) as bundle:
            entries = _safe_members(bundle, jar=False)
            if bundle.testzip() is not None:
                raise BAppPreflightError("bapp_crc_failure")
            signature = bundle.read("BappSignature.sig")
            if not 64 <= len(signature) <= 4096:
                raise BAppPreflightError("signature_blob_size")
            if _digest(signature) != expected_signature_sha256:
                raise BAppPreflightError("signature_digest_mismatch")
            vendor_manifest = bundle.read("BappManifest.bmf")
            if source_manifest.stat().st_size > 8192:
                raise BAppPreflightError("source_manifest_size_limit")
            if vendor_manifest != source_manifest.read_bytes():
                raise BAppPreflightError("source_manifest_mismatch")
            bapp = _manifest(vendor_manifest)
            if (
                bapp.get("Uuid") != expected_uuid
                or bapp.get("Name") != "MCP Server"
                or bapp.get("ScreenVersion") != expected_version
                or bapp.get("SerialVersion") != str(expected_serial)
                or bapp.get("EntryPoint") != "burp-mcp-all.jar"
                or bapp.get("RepoName") != "mcp-server"
                or bapp.get("ExtensionType") != "1"
            ):
                raise BAppPreflightError("vendor_manifest_identity_mismatch")
            jar_bytes = bundle.read("burp-mcp-all.jar")
            if not jar_bytes.startswith(b"PK\x03\x04"):
                raise BAppPreflightError("invalid_nested_jar")
            with zipfile.ZipFile(io.BytesIO(jar_bytes)) as jar:
                jar_entries = _safe_members(jar, jar=True)
                if "META-INF/MANIFEST.MF" not in jar_entries:
                    raise BAppPreflightError("jar_manifest_missing")
                if jar.testzip() is not None:
                    raise BAppPreflightError("jar_crc_failure")
                jar_manifest = _manifest(jar.read("META-INF/MANIFEST.MF"))
                if (
                    jar_manifest.get("Implementation-Version") != expected_version
                    or jar_manifest.get("Implementation-Vendor") != "PortSwigger"
                ):
                    raise BAppPreflightError("jar_manifest_version_mismatch")
                jar_count = len(jar_entries)
            member_digests = {
                name: {"sha256": _digest(bundle.read(name)), "size_bytes": entries[name].file_size}
                for name in sorted(EXPECTED_FILES)
            }
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise BAppPreflightError("archive_structural_error") from exc
    return {
        "schema": "aegisscan.g3.bapp-supplier-preflight.v1",
        "scope": "offline_structural_and_exact_source_integrity_only",
        "archive_sha256": archive_digest,
        "source_manifest_sha256": _digest(vendor_manifest),
        "signature_blob_sha256": _digest(signature),
        "bapp_uuid": bapp["Uuid"],
        "bapp_version": bapp["ScreenVersion"],
        "serial_version": expected_serial,
        "jar_entries_checked": jar_count,
        "jar_manifest_built_date_observed": jar_manifest.get("Built-Date", ""),
        "members": member_digests,
        "checks": {
            "bounded_structure_and_crc": True,
            "manifest_byte_matches_pinned_source": True,
            "local_sha256_pins_match": True,
            "jar_version_matches_bapp_version": True,
            "cryptographic_publisher_signature_verified": False,
            "publisher_trust_anchor_authenticated": False,
            "supplier_sbom_verified": False,
            "supplier_provenance_verified": False,
            "reproducible_build_independently_verified": False,
        },
        "governance": {
            "admission": "BLOCKED",
            "provider_trusted": False,
            "provider_approved": False,
            "production_installed": False,
            "lab_solved": False,
        },
        "limitations": [
            "A signature blob is not proof that a trusted vendor signed these bytes.",
            "Hashes/manifest provided by the same untrusted download are not independent publisher attestations.",
            "No signer verification key, authenticated SBOM, builder provenance or reproducible build was supplied.",
            "Byte-identical reproducibility remains unproven; the vendor JAR embeds a Built-Date field.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--expected-signature-sha256", required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--expected-uuid", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-serial", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = audit(
            args.archive,
            expected_archive_sha256=args.expected_archive_sha256,
            expected_signature_sha256=args.expected_signature_sha256,
            source_manifest=args.source_manifest,
            expected_uuid=args.expected_uuid,
            expected_version=args.expected_version,
            expected_serial=args.expected_serial,
        )
        # Never clobber prior evidence; generate only after all checks finish.
        with open(args.output, "x", encoding="utf-8", opener=lambda p, f: __import__("os").open(p, f, 0o600)) as out:
            out.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    except (BAppPreflightError, FileExistsError, FileNotFoundError, PermissionError) as exc:
        print(f"BAPP_OFFLINE_PREFLIGHT_FAIL: {exc}")
        return 1
    print("BAPP_OFFLINE_INTEGRITY_PASS__SUPPLIER_ADMISSION_BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
