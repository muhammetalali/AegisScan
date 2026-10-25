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
        self.ca_config = conf
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

    def _issue_synthetic_server_leaf(self) -> Path:
        """Issue a synthetic leaf through the EXISTING test CA ledger, not production."""
        leaf_key = self.root / "synthetic-server.key"
        request = self.root / "synthetic-server.csr"
        leaf = self.root / "synthetic-server.pem"
        run(
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(leaf_key), "-out", str(request),
            "-subj", "/CN=aegis-prod.aegis.internal",
        )
        os.chmod(leaf_key, 0o600)
        extensions = self.root / "synthetic-leaf-ext.cnf"
        extensions.write_text(
            "[v3_leaf]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:aegis-prod.aegis.internal\n"
            "crlDistributionPoints=URI:http://aegis-prod.aegis.internal/pki/aegisscan-root-ca.crl\n"
            "authorityInfoAccess=caIssuers;URI:http://aegis-prod.aegis.internal/pki/aegisscan-root-ca.cer\n"
        )
        run(
            "ca", "-batch", "-notext", "-days", "2",
            "-config", str(self.ca_config),
            "-extfile", str(extensions), "-extensions", "v3_leaf",
            "-in", str(request), "-out", str(leaf),
        )
        return leaf

    def _renew_synthetic_crl(self) -> None:
        """Regenerate a genuine signed CRL from the test CA database."""
        pem = self.root / "synthetic-updated.crl.pem"
        run("ca", "-gencrl", "-batch", "-config", str(self.ca_config), "-out", str(pem))
        self.test_crl_pem = pem
        self.crl.write_bytes(run("crl", "-in", str(pem), "-outform", "DER"))

    def test_leaf_cdp_aia_good_then_revoked_is_rejected(self) -> None:
        """The same synthetic issuer/CRL contract supports accept and revoke."""
        leaf = self._issue_synthetic_server_leaf()
        details = run("x509", "-in", str(leaf), "-noout", "-text").decode()
        self.assertIn("DNS:aegis-prod.aegis.internal", details)
        self.assertIn(
            "URI:http://aegis-prod.aegis.internal/pki/aegisscan-root-ca.crl",
            details,
        )
        self.assertIn(
            "CA Issuers - URI:http://aegis-prod.aegis.internal/pki/aegisscan-root-ca.cer",
            details,
        )
        self._renew_synthetic_crl()
        good = subprocess.run(
            [
                "openssl", "verify", "-purpose", "sslserver", "-crl_check",
                "-CAfile", str(self.cert), "-CRLfile", str(self.test_crl_pem), str(leaf),
            ],
            capture_output=True, timeout=25, check=False,
        )
        self.assertEqual(good.returncode, 0, good.stderr.decode(errors="replace"))
        self.assertTrue(good.stdout.strip().endswith(b": OK"))
        self.assertEqual(self.check()["production_pki_acceptance"], "NOT_IMPLIED")

        run("ca", "-batch", "-config", str(self.ca_config), "-revoke", str(leaf))
        self._renew_synthetic_crl()
        revoked = subprocess.run(
            [
                "openssl", "verify", "-purpose", "sslserver", "-crl_check",
                "-CAfile", str(self.cert), "-CRLfile", str(self.test_crl_pem), str(leaf),
            ],
            capture_output=True, timeout=25, check=False,
        )
        self.assertNotEqual(revoked.returncode, 0)
        self.assertIn(
            b"certificate revoked",
            (revoked.stdout + revoked.stderr).lower(),
        )
        # Crypto admission checks CRL authenticity, not individual leaf status:
        # the separate explicit revocation acceptance above is mandatory.
        self.assertEqual(self.check()["production_pki_acceptance"], "NOT_IMPLIED")

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
        b[-1] ^= 0x01  # The DER CRL ends in the signed BIT STRING.
        self.crl.write_bytes(b)
        with self.assertRaises(pki.ArtifactRejected):
            self.check()

    def test_openssl_zero_exit_with_verify_failure_is_rejected(self) -> None:
        """Some OpenSSL CLI builds can return 0 despite 'verify failure'."""
        from unittest.mock import patch

        fake = subprocess.CompletedProcess(
            args=["openssl", "crl"], returncode=0,
            stdout=b"", stderr=b"verify failure\n",
        )
        with patch.object(pki.subprocess, "run", return_value=fake):
            with self.assertRaises(pki.ArtifactRejected):
                pki._verify_signed_crl(self.crl, self.cert)

    def test_openssl_zero_exit_without_explicit_verify_ok_rejected(self) -> None:
        from unittest.mock import patch

        fake = subprocess.CompletedProcess(
            args=["openssl", "crl"], returncode=0,
            stdout=b"", stderr=b"",
        )
        with patch.object(pki.subprocess, "run", return_value=fake):
            with self.assertRaises(pki.ArtifactRejected):
                pki._verify_signed_crl(self.crl, self.cert)

    def test_openssl_explicit_verify_ok_is_accepted(self) -> None:
        from unittest.mock import patch

        fake = subprocess.CompletedProcess(
            args=["openssl", "crl"], returncode=0,
            stdout=b"", stderr=b"verify OK\n",
        )
        with patch.object(pki.subprocess, "run", return_value=fake):
            pki._verify_signed_crl(self.crl, self.cert)

    def test_nonzero_exit_with_verify_ok_text_rejected(self) -> None:
        from unittest.mock import patch

        fake = subprocess.CompletedProcess(
            args=["openssl", "crl"], returncode=1,
            stdout=b"", stderr=b"verify OK\n",
        )
        with patch.object(pki.subprocess, "run", return_value=fake):
            with self.assertRaises(pki.ArtifactRejected):
                pki._verify_signed_crl(self.crl, self.cert)

    def test_conflicting_output_with_verify_ok_rejected(self) -> None:
        from unittest.mock import patch

        fake = subprocess.CompletedProcess(
            args=["openssl", "crl"], returncode=0,
            stdout=b"verify failure\n", stderr=b"verify OK\n",
        )
        with patch.object(pki.subprocess, "run", return_value=fake):
            with self.assertRaises(pki.ArtifactRejected):
                pki._verify_signed_crl(self.crl, self.cert)

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
