"""Offline synthetic-CA tests. Never use the production CA key or host ledger."""
from __future__ import annotations

import hashlib
import importlib.util
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


TOOL_PATH = Path(__file__).resolve().parents[1] / "aegis-platform/scripts/production_internal_pki_verify.py"
spec = importlib.util.spec_from_file_location("production_internal_pki_verify", TOOL_PATH)
assert spec and spec.loader
pki = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pki)


def run(*args: str) -> bytes:
    return subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=25).stdout


class PublicPKIAdmission(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="g4-synthetic-public-pki-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pub = self.root / "pki-public"
        self.pub.mkdir(mode=0o755)
        self.key = self.root / "test-only.key"
        self.cert = self.root / "test-only-root.pem"
        run(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            "-keyout", str(self.key), "-out", str(self.cert),
            "-subj", "/CN=Ephemeral Test-Only Root",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )
        os.chmod(self.key, 0o600)
        self.root_fingerprint = hashlib.sha256(
            run("x509", "-in", str(self.cert), "-outform", "DER")
        ).hexdigest()
        cert_der = self.pub / "aegisscan-root-ca.cer"
        cert_der.write_bytes(run("x509", "-in", str(self.cert), "-outform", "DER"))
        self.crl = self.pub / "aegisscan-root-ca.crl"
        (self.root / "index.txt").write_text("")
        (self.root / "crlnumber").write_text("1000\n")
        (self.root / "serial").write_text("1000\n")
        (self.root / "newcerts").mkdir()
        conf = self.root / "test-only.cnf"
        conf.write_text(
            "[ca]\ndefault_ca=ca_default\n[ca_default]\n"
            f"database={self.root / 'index.txt'}\n"
            f"new_certs_dir={self.root / 'newcerts'}\n"
            f"certificate={self.cert}\n"
            f"private_key={self.key}\n"
            f"serial={self.root / 'serial'}\n"
            f"crlnumber={self.root / 'crlnumber'}\n"
            "default_md=sha256\ndefault_crl_days=7\n"
            "policy=policy_match\n[policy_match]\ncommonName=supplied\n"
        )
        pem_crl = self.root / "test-only.crl.pem"
        run("ca", "-gencrl", "-batch", "-config", str(conf), "-out", str(pem_crl))
        self.crl.write_bytes(run("crl", "-in", str(pem_crl), "-outform", "DER"))
        os.chmod(self.crl, 0o644)
        os.chmod(cert_der, 0o644)

    def check(self, *, now: datetime | None = None) -> dict[str, str]:
        return pki.verify_artifacts(
            self.pub,
            self.cert,
            expected_root_sha256=self.root_fingerprint,
            now=now,
        )

    def test_valid_signed_synthetic_crl_is_crypto_only_not_ledger_proof(self) -> None:
        result = self.check()
        self.assertEqual(result["historical_ca_issuance_and_revocation_ledger"], "NOT_VERIFIED")
        self.assertEqual(result["production_pki_acceptance"], "NOT_IMPLIED")
        self.assertEqual(result["root_sha256"], self.root_fingerprint)

    def test_missing_signed_crl_rejected(self) -> None:
        self.crl.unlink()
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_tampered_crl_rejected(self) -> None:
        b = bytearray(self.crl.read_bytes())
        b[len(b) // 2] ^= 0x01
        self.crl.write_bytes(b)
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_replaced_root_issuer_rejected(self) -> None:
        p = self.pub / "aegisscan-root-ca.cer"
        p.write_bytes(b"invalid-der")
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_pinned_root_fingerprint_rejected(self) -> None:
        with self.assertRaises(pki.ArtifactRejected):
            pki.verify_artifacts(self.pub, self.cert)

    def test_future_and_expired_crl_rejected(self) -> None:
        with self.assertRaises(pki.ArtifactRejected):
            self.check(now=datetime.now(timezone.utc) + timedelta(days=8))
        with self.assertRaises(pki.ArtifactRejected):
            self.check(now=datetime.now(timezone.utc) - timedelta(days=1))

    def test_unsafe_artifact_mode_rejected(self) -> None:
        self.crl.chmod(0o666)
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_extra_public_file_rejected(self) -> None:
        (self.pub / "unexpected.key").write_text("not a key")
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_symlinked_crl_rejected(self) -> None:
        target = self.root / "out-of-pub.der"
        self.crl.replace(target)
        self.crl.symlink_to(target)
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_not_world_traversable_dir_rejected(self) -> None:
        self.pub.chmod(0o700)
        with self.assertRaises(pki.ArtifactRejected):
            self.check()


if __name__ == "__main__":
    unittest.main()
