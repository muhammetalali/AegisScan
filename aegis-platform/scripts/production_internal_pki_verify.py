#!/usr/bin/env python3
"""Read-only public PKI artifact validation; never signs or publishes CRLs.

A valid signature is NECESSARY, not proof of complete historic CA revocation
records. The final operational gate independently requires issuer-ledger
provenance, human acceptance, leaf CDP/AIA and strict Schannel proof.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ORIGINAL_ROOT_FINGERPRINT = "1bd1ef20805cd8a45413356e1902c87803a030395b5f1cfeeb89a39466d6d8f8"
PUBLIC_NAMES = {"aegisscan-root-ca.crl", "aegisscan-root-ca.cer", ".gitignore", "README.md"}


class ArtifactRejected(ValueError):
    pass


def _openssl(*args: str) -> bytes:
    try:
        return subprocess.run(
            ["openssl", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise ArtifactRejected("OpenSSL certificate/CRL verification failed") from exc


def _verify_signed_crl(crl: Path, root_pem: Path) -> None:
    """Require explicit OpenSSL success, never just its exit status.

    OpenSSL releases differ in whether CRL signature checking exits nonzero
    after reporting "verify failure". An exit-zero response without
    the exact success marker is not cryptographic verification.
    """
    try:
        result = subprocess.run(
            [
                "openssl", "crl", "-inform", "DER", "-in", str(crl),
                "-CAfile", str(root_pem), "-verify", "-noout",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise ArtifactRejected("OpenSSL CRL signature verification unavailable") from exc

    # Treat any extra diagnostics (including a misleading verification
    # failure alongside an OK line) as a failure. Accept stdout or stderr.
    verdict = (result.stdout + b"\n" + result.stderr).strip()
    if result.returncode != 0 or verdict != b"verify OK":
        raise ArtifactRejected("CRL signature verification did not return explicit verify OK")


def _public_file(path: Path, *, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ArtifactRejected("Required public artifact missing or is a symlink")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o022 or mode & 0o004 != 0o004:
        raise ArtifactRejected("Public artifact permissions are not safe/readable")
    size = path.stat().st_size
    if not 0 < size <= limit:
        raise ArtifactRejected("Public artifact missing or exceeds size limit")
    return path.read_bytes()


def _asn1_time(s: str, key: str) -> datetime:
    prefix = key + "="
    value = next((line[len(prefix):] for line in s.splitlines() if line.startswith(prefix)), "")
    if not value:
        raise ArtifactRejected("CRL is missing " + key)
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ArtifactRejected("Invalid " + key + " in CRL") from exc


def verify_artifacts(
    public_dir: Path,
    root_pem: Path,
    *,
    expected_root_sha256: str = ORIGINAL_ROOT_FINGERPRINT,
    now: datetime | None = None,
) -> dict[str, str]:
    """Reject malformed, substituted, stale, inaccessible and unsigned artifacts."""
    public_dir = Path(public_dir)
    if public_dir.is_symlink() or not public_dir.is_dir():
        raise ArtifactRejected("Public artifact directory missing or symlinked")
    dm = stat.S_IMODE(public_dir.stat().st_mode)
    if (dm & 0o005) != 0o005 or dm & 0o022:
        raise ArtifactRejected("Public directory must be non-writable and traversable by Nginx")

    found = {p.name for p in public_dir.iterdir()}
    if found - PUBLIC_NAMES:
        raise ArtifactRejected("Unexpected file in public-only directory")

    crl = public_dir / "aegisscan-root-ca.crl"
    cer = public_dir / "aegisscan-root-ca.cer"
    crl_bytes = _public_file(crl, limit=4 * 1024 * 1024)
    issuer_bytes = _public_file(cer, limit=128 * 1024)

    root_der = _openssl("x509", "-in", str(root_pem), "-outform", "DER")
    if hashlib.sha256(root_der).hexdigest() != expected_root_sha256.lower().replace(":", ""):
        raise ArtifactRejected("Trusted root fingerprint does not match the independently pinned CA")
    issuer_der = _openssl("x509", "-inform", "DER", "-in", str(cer), "-outform", "DER")
    if issuer_der != root_der or issuer_bytes != issuer_der:
        raise ArtifactRejected("Published DER issuer certificate differs from the trusted original root")

    _openssl("x509", "-in", str(root_pem), "-checkend", "0", "-noout")
    _verify_signed_crl(crl, root_pem)
    dates = _openssl("crl", "-inform", "DER", "-in", str(crl), "-noout", "-lastupdate", "-nextupdate").decode()
    last = _asn1_time(dates, "lastUpdate")
    future = _asn1_time(dates, "nextUpdate")
    current = now or datetime.now(timezone.utc)
    if not (last <= current + timedelta(minutes=5) < future) or last >= future:
        raise ArtifactRejected("CRL is stale, not yet valid or has invalid update ordering")

    return {
        "root_sha256": hashlib.sha256(root_der).hexdigest(),
        "issuer_der_sha256": hashlib.sha256(issuer_bytes).hexdigest(),
        "crl_der_sha256": hashlib.sha256(crl_bytes).hexdigest(),
        "crl_this_update_utc": last.isoformat(),
        "crl_next_update_utc": future.isoformat(),
        "historical_ca_issuance_and_revocation_ledger": "NOT_VERIFIED",
        "production_pki_acceptance": "NOT_IMPLIED",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only G4 public PKI transport crypto preflight")
    default_public = Path(__file__).resolve().parents[1] / "docker" / "pki-public"
    parser.add_argument("--profile", choices=("original", "successor"), default="original")
    parser.add_argument("--public-dir", type=Path)
    parser.add_argument("--root-cert", type=Path)
    parser.add_argument(
        "--successor-root-sha256",
        help="Independently authorized 64-character SHA-256 of the NEW public CA certificate",
    )
    args = parser.parse_args()
    if args.profile == "original":
        if args.successor_root_sha256 is not None:
            parser.error("--successor-root-sha256 is forbidden for the original pinned CA")
        public_dir = args.public_dir or default_public
        root_cert = args.root_cert or Path("/usr/local/share/ca-certificates/aegisscan-enterprise.crt")
        expected_sha256 = ORIGINAL_ROOT_FINGERPRINT
    else:
        # Never infer or auto-trust a successor from its presented certificate.
        # The operator must separately approve and supply its public fingerprint.
        if args.public_dir is None or args.root_cert is None:
            parser.error("successor requires explicit --public-dir and --root-cert")
        if not args.successor_root_sha256 or re.fullmatch(
            r"[0-9a-fA-F]{64}", args.successor_root_sha256
        ) is None:
            parser.error("successor requires an independently verified 64-hex --successor-root-sha256")
        expected_sha256 = args.successor_root_sha256.lower()
        if expected_sha256 == ORIGINAL_ROOT_FINGERPRINT:
            parser.error("successor must never reuse the original pinned CA identity")
        public_dir = args.public_dir
        root_cert = args.root_cert

    try:
        findings = verify_artifacts(
            public_dir, root_cert, expected_root_sha256=expected_sha256,
        )
    except ArtifactRejected as exc:
        print("G4_PUBLIC_PKI_CRYPTO=NOT_READY", file=sys.stderr)
        print("G4_PUBLIC_PKI_REASON=" + str(exc), file=sys.stderr)
        print("G4_HISTORICAL_CA_LEDGER=NOT_VERIFIED", file=sys.stderr)
        return 3
    print("G4_PUBLIC_PKI_CRYPTO=PASS")
    print("G4_PUBLIC_PKI_PROFILE=" + args.profile)
    for key, value in findings.items():
        print(f"{key.upper()}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
