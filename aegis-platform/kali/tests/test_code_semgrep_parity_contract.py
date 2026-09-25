from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "runner" / "code_semgrep_parity_service.py"
SPEC = importlib.util.spec_from_file_location("code_semgrep_parity_service", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class GovernedSemgrepParityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        source = root / "source"
        source.mkdir()
        (source / "app.py").write_text("def f(x):\n    return eval(x)\n", encoding="utf-8")
        rule = root / "semgrep-parity.yml"
        rule.write_text("rules: []\n", encoding="utf-8")
        self.config = MODULE.Config(
            auth_token="a" * 64,
            authorization_ref="authorization:parity",
            scope_ref="project:parity:asset:code",
            source_ref="fixture:semgrep-parity:v1",
            source_root=source,
            source_sha256=MODULE._tree_sha256(source),
            rule_path=rule,
            rule_sha256=MODULE._file_sha256(rule),
        )
        self.payload = {
            "schema_version": 1,
            "execution_ref": "scan:parity:semgrep",
            "authorization_ref": self.config.authorization_ref,
            "scope_ref": self.config.scope_ref,
            "capability_id": "code.semgrep",
            "source_ref": self.config.source_ref,
            "timeout_seconds": 120,
        }

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_valid_payload_binds_authority_scope_source_and_timeout(self) -> None:
        validated = MODULE.validate_payload(dict(self.payload), self.config)
        self.assertEqual(validated["execution_ref"], "scan:parity:semgrep")
        self.assertEqual(validated["timeout_seconds"], 120)

    def test_unknown_field_is_rejected(self) -> None:
        payload = dict(self.payload)
        payload["unexpected"] = "value"
        with self.assertRaisesRegex(MODULE.RequestError, "unknown request fields"):
            MODULE.validate_payload(payload, self.config)

    def test_binding_mismatch_fails_closed(self) -> None:
        for field, value in (
            ("authorization_ref", "authorization:other"),
            ("scope_ref", "project:other:asset:code"),
            ("source_ref", "fixture:other"),
        ):
            with self.subTest(field=field):
                payload = dict(self.payload)
                payload[field] = value
                with self.assertRaises(MODULE.RequestError):
                    MODULE.validate_payload(payload, self.config)

    def test_boolean_or_unbounded_timeout_is_rejected(self) -> None:
        for timeout in (True, 0, 901):
            with self.subTest(timeout=timeout):
                payload = dict(self.payload)
                payload["timeout_seconds"] = timeout
                with self.assertRaises(MODULE.RequestError):
                    MODULE.validate_payload(payload, self.config)

    def test_source_tree_digest_changes_with_content(self) -> None:
        before = self.config.source_sha256
        (self.config.source_root / "app.py").write_text("print('changed')\n", encoding="utf-8")
        after = MODULE._tree_sha256(self.config.source_root)
        self.assertNotEqual(before, after)

    def test_source_tree_rejects_symlinks(self) -> None:
        outside = Path(self.tempdir.name) / "outside.py"
        outside.write_text("pass\n", encoding="utf-8")
        (self.config.source_root / "linked.py").symlink_to(outside)
        with self.assertRaisesRegex(SystemExit, "cannot contain symlinks"):
            MODULE._tree_sha256(self.config.source_root)

    def test_runtime_version_probe_uses_writable_temporary_home(self) -> None:
        class Completed:
            returncode = 0
            stdout = "1.177.0\n"
            stderr = ""

        with patch.object(
            MODULE,
            "_read_proc_status",
            return_value={
                "Uid": "10001 10001 10001 10001",
                "CapEff": "0000000000000000",
                "NoNewPrivs": "1",
            },
        ), patch.object(MODULE.subprocess, "run", return_value=Completed()) as run:
            runtime = MODULE._runtime_identity(self.config)

        env = run.call_args.kwargs["env"]
        self.assertTrue(env["HOME"].startswith("/tmp/aegis-semgrep-version-"))
        self.assertTrue(env["XDG_CONFIG_HOME"].startswith("/tmp/aegis-semgrep-version-"))
        self.assertTrue(env["XDG_CACHE_HOME"].startswith("/tmp/aegis-semgrep-version-"))
        self.assertEqual(env["SEMGREP_SEND_METRICS"], "off")
        self.assertEqual(env["SEMGREP_ENABLE_VERSION_CHECK"], "0")
        self.assertEqual(runtime["tool_version"], "1.177.0")

    def test_service_is_loopback_only(self) -> None:
        self.assertEqual(MODULE.LISTEN_HOST, "127.0.0.1")
        self.assertEqual(MODULE.CAPABILITY_ID, "code.semgrep")

    def test_legacy_runtime_semgrep_pin_matches_governed_manifest(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        requirements = (repo_root / "aegis-platform" / "backend" / "requirements.txt").read_text(
            encoding="utf-8"
        )
        dockerfile = (repo_root / "aegis-platform" / "backend" / "Dockerfile.django").read_text(
            encoding="utf-8"
        )
        manifest = (repo_root / "aegis-platform" / "kali" / "tool-manifest.json").read_text(
            encoding="utf-8"
        )

        import json

        semgrep_version = json.loads(manifest)["tools"]["semgrep"]["version"]
        self.assertIn(f"semgrep=={semgrep_version}", requirements)
        self.assertNotIn(
            "python -m pip install --no-cache-dir semgrep ",
            dockerfile,
        )


if __name__ == "__main__":
    unittest.main()
