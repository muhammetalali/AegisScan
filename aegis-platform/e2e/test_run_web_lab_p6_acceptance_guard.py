from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "run_web_lab_p6_acceptance.py"
SPEC = importlib.util.spec_from_file_location("run_web_lab_p6_acceptance", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class P6AcceptanceGuardTests(unittest.TestCase):
    def test_control_container_is_p6_specific(self):
        self.assertEqual(MODULE.CONTROL, "aegis-burp-p6-control")
        self.assertNotEqual(MODULE.CONTROL, "aegis-burp-p5-control")

    def test_load_env_forces_dedicated_p6_backends_and_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "env.json"
            path.write_text(
                json.dumps(
                    {
                        "AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1",
                        "UNRELATED": "kept",
                    }
                )
            )
            env = MODULE.load_env(path, "a" * 40)

        self.assertNotIn("AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF", env)
        self.assertEqual(env["AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF"], "1")
        self.assertTrue(env["DATABASE_URL"].endswith("/burp_p6"))
        self.assertTrue(env["CELERY_BROKER_URL"].endswith("/2"))
        self.assertEqual(env["AEGIS_PROOF_SOURCE_COMMIT"], "a" * 40)
        self.assertEqual(env["UNRELATED"], "kept")

    def test_acceptance_lock_rejects_parallel_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = MODULE.acquire_acceptance_lock(Path(tmp))
            try:
                with self.assertRaisesRegex(MODULE.AcceptanceError, "already running"):
                    MODULE.acquire_acceptance_lock(Path(tmp))
            finally:
                first.close()

    def test_burp_profile_requires_packaged_mcp_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp)
            data = profile / "data"
            data.mkdir()
            config = data / "UserConfig.json"
            config.write_text(json.dumps({
                "user_options": {"extender": {"extensions": [{
                    "loaded": True,
                    "extension_type": "java",
                    "extension_file": "/opt/burp/burp-mcp-all.jar",
                }]}}
            }))
            digest = MODULE.validate_burp_profile(profile)
            self.assertEqual(len(digest), 64)

            config.write_text(json.dumps({
                "user_options": {"extender": {"extensions": [{
                    "loaded": True,
                    "extension_type": "java",
                    "extension_file": "/home/user/burp-mcp-all.jar",
                }]}}
            }))
            with self.assertRaisesRegex(MODULE.AcceptanceError, "packaged MCP extension"):
                MODULE.validate_burp_profile(profile)

    def test_secure_base_is_fail_closed(self):
        args = MODULE.secure_base(
            {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
            "sha256:" + "1" * 64,
        )
        joined = " ".join(args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop ALL", joined)
        self.assertIn("no-new-privileges:true", args)
        self.assertIn("container:aegis-burp-p2-egress", args)
        self.assertEqual(args[-1], "sha256:" + "1" * 64)


if __name__ == "__main__":
    unittest.main()
