from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


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

    def test_runtime_profile_is_cloned_without_reusing_session_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed"
            data = seed / "data"
            sessions = data / "sessions"
            sessions.mkdir(parents=True)
            (sessions / "stale.run").write_text("must-not-be-reused")
            (seed / "prefs").mkdir()
            config = data / "UserConfig.json"
            config.write_text(json.dumps({
                "user_options": {"extender": {"extensions": [{
                    "loaded": True,
                    "extension_type": "java",
                    "extension_file": "/opt/burp/burp-mcp-all.jar",
                }]}}
            }))
            destination = root / "runtime"

            result = MODULE.clone_burp_runtime_profile(seed, destination)

            self.assertEqual(result, destination)
            self.assertTrue((seed / "data/sessions/stale.run").is_file())
            self.assertEqual(list((destination / "data/sessions").iterdir()), [])
            self.assertEqual(
                MODULE.validate_burp_profile(destination),
                MODULE.validate_burp_profile(seed),
            )

    def test_prime_command_pins_root_sse_and_exact_fixture_target(self):
        command = MODULE.burp_prime_command("sha256:" + "a" * 64, "p6-prime")
        joined = " ".join(command)
        self.assertIn("--read-only", command)
        self.assertIn("--cap-drop ALL", joined)
        self.assertIn("no-new-privileges:true", command)
        self.assertIn("container:aegis-burp-p2-egress", command)
        self.assertIn("/app/scripts/burp_mcp_sse_probe.py", command)
        endpoint_index = command.index("--endpoint") + 1
        target_index = command.index("--target") + 1
        self.assertEqual(command[endpoint_index], "http://127.0.0.1:9876/")
        self.assertNotIn("/sse", command[endpoint_index])
        self.assertEqual(command[target_index], "http://127.0.0.1:18081")

    def test_x11_expected_windows_ignores_hidden_transient_matches(self):
        hidden = {
            "x": 0,
            "y": 0,
            "width": 1,
            "height": 1,
            "state": "IsUnMapped",
        }
        visible = {
            "x": 233,
            "y": 156,
            "width": 814,
            "height": 521,
            "state": "IsViewable",
        }
        with (
            mock.patch.object(MODULE, "x11_window_ids", return_value={0x10, 0x20}),
            mock.patch.object(
                MODULE,
                "x11_window_geometry",
                side_effect=lambda window_id, _xauthority: (
                    hidden if window_id == 0x10 else visible
                ),
            ),
        ):
            matches = MODULE.x11_expected_windows(
                MODULE.BURP_STARTUP_TITLE,
                set(),
                Path("/tmp/xauth"),
                MODULE.BURP_STARTUP_SIZE,
            )

        self.assertEqual(set(matches), {0x20})
        self.assertEqual(matches[0x20], visible)

    def test_community_bootstrap_is_exact_window_and_two_bounded_clicks(self):
        geometry = {
            "x": 10,
            "y": 20,
            "width": 814,
            "height": 521,
            "state": "IsViewable",
        }
        with (
            mock.patch.object(
                MODULE,
                "wait_new_x11_window",
                side_effect=[0x100, 0x200],
            ),
            mock.patch.object(
                MODULE,
                "require_x11_geometry",
                side_effect=[geometry, geometry, {
                    "x": 0,
                    "y": 33,
                    "width": 1280,
                    "height": 767,
                    "state": "IsViewable",
                }],
            ),
            mock.patch.object(
                MODULE,
                "x11_window_ids",
                return_value={0x100},
            ),
            mock.patch.object(MODULE, "x11_click_relative") as click,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            evidence = MODULE.automate_burp_community_startup(
                xauthority=Path("/tmp/xauth"),
                startup_before=set(),
                main_before=set(),
            )

        self.assertEqual(click.call_count, 2)
        self.assertEqual(
            [call.args[3] for call in click.call_args_list],
            [MODULE.BURP_WIZARD_BUTTON, MODULE.BURP_WIZARD_BUTTON],
        )
        self.assertEqual(evidence["human_interventions"], 0)
        self.assertEqual(
            evidence["wizard_steps"],
            ["temporary_project_in_memory", "use_burp_defaults"],
        )

    def test_approval_is_host_port_scoped_and_ui_contract_is_pinned(self):
        self.assertEqual(MODULE.BURP_APPROVAL_TARGET, "http://127.0.0.1:18081")
        self.assertEqual(MODULE.BURP_APPROVAL_MODAL_TITLE, " ")
        self.assertEqual(MODULE.BURP_APPROVAL_MODAL_SIZE, (860, 400))
        self.assertEqual(MODULE.BURP_APPROVAL_HOST_PORT_BUTTON, (565, 354))
        self.assertNotEqual(
            MODULE.BURP_APPROVAL_HOST_PORT_BUTTON,
            MODULE.BURP_WIZARD_BUTTON,
        )

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
