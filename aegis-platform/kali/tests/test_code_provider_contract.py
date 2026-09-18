from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "runner" / "code_service.py"
SPEC = importlib.util.spec_from_file_location("code_service", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class GovernedCodeProviderContractTests(unittest.TestCase):
    def test_service_is_loopback_only_and_semgrep_only(self) -> None:
        self.assertEqual(MODULE._LISTEN_HOST, "127.0.0.1")
        self.assertEqual(MODULE._LISTEN_PORT, 18771)
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("'code.semgrep'", source)
        self.assertIn("semantic-code-provider", source)
        self.assertIn("shell=False", source)
        self.assertNotIn("shell=True", source)

    def test_source_entry_rejects_escape_and_absolute_paths(self) -> None:
        for value in ("../outside", "/etc/passwd", "a/../../b"):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.ProtocolError):
                    MODULE._validate_source_entry(value)
        self.assertEqual(MODULE._validate_source_entry("."), ".")
        self.assertEqual(MODULE._validate_source_entry("src/app.py"), "src/app.py")

    def test_tree_digest_is_stable_and_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as holder:
            root = Path(holder)
            (root / "a.py").write_text("print('a')\n", encoding="utf-8")
            first = MODULE._tree_sha256(root)
            second = MODULE._tree_sha256(root)
            self.assertEqual(first, second)
            target = root / "real.py"
            target.write_text("pass\n", encoding="utf-8")
            (root / "linked.py").symlink_to(target)
            with self.assertRaisesRegex(MODULE.ProtocolError, "symlink"):
                MODULE._tree_sha256(root)

    def test_request_cannot_choose_binary_config_or_raw_path(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("payload['config']", source)
        self.assertNotIn('payload["config"]', source)
        self.assertNotIn("payload['argv']", source)
        self.assertNotIn('payload["argv"]', source)
        self.assertNotIn("payload['path']", source)
        self.assertNotIn('payload["path"]', source)
        self.assertIn("AEGIS_CODE_SEMGREP_CONFIG", source)
        self.assertIn("AEGIS_CODE_WORKSPACE_ROOT", source)


if __name__ == "__main__":
    unittest.main()
