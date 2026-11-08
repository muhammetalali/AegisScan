"""Offline regression tests for the host-only external Web Lab preflight."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name("audit_external_web_lab_readiness.py")
spec = importlib.util.spec_from_file_location("audit_external_web_lab_readiness", MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

PROJECT = "6e1de003-ccf2-4549-a2ce-6520ab9bc046"
TARGET = "https://challenge.cyberpedia.site"
ASSET = {
    "asset_id": "1ce3b319-fc7d-4d33-9f2e-e67168423b82",
    "authorized": True, "authorization_ref": PROJECT,
    "authorization_state": "current",
}
READY_DB = {
    "project_active": True, "tenant_bindings": 1, "assets": [ASSET],
    "provider": {"state": "metadata_ready", "decision_ref": PROJECT},
    "approved_operations": ["burp.http_request"],
    "matching_active_credential_metadata": 2,
}
MCP_OK = {"http_status": 200, "content_type": "text/event-stream"}


class TestInput(unittest.TestCase):
    def test_normalizes_root(self):
        self.assertEqual(audit.normalize_target(TARGET), TARGET + "/")
        self.assertEqual(audit.normalize_target(TARGET + ":443/"), TARGET + "/")

    def test_rejects_non_application_inputs(self):
        cases = [
            "http://challenge.cyberpedia.site",
            TARGET + "/admin", TARGET + "/?token=secret",
            TARGET + "/#top", "https://user:pass@challenge.cyberpedia.site",
            "https://challenge..cyberpedia.site/", "https://",
            TARGET + "\n", "javascript:alert(1)",
        ]
        for target in cases:
            with self.subTest(target=target), self.assertRaises(ValueError):
                audit.normalize_target(target)

    def test_rejects_bad_project_uuid_before_docker(self):
        with patch.object(audit, "run_json") as probe:
            with self.assertRaises(ValueError):
                audit.collect("not-a-uuid", TARGET, check_mcp=True)
            probe.assert_not_called()


class TestExternalLabDefinition(unittest.TestCase):
    def test_planned_cyberpedia_contract_is_never_executable(self):
        import json
        manifest = MODULE.parents[2] / "docs/web-labs/cyberpedia-northwind-auth-otp.v1.json"
        data = json.loads(manifest.read_text())
        self.assertEqual(data["origin"], TARGET)
        self.assertEqual(data["authorization"]["approved_scope"], [TARGET + "/"])
        self.assertEqual(data["execution"]["stage"], "DEFINITION_ONLY")
        self.assertFalse(data["execution"]["automated_execution_enabled"])
        self.assertFalse(data["execution"]["lab_solved"])
        self.assertEqual(data["observed_client_contract"]["otp_submit"]["path"], "/api/otp")
        self.assertEqual(data["observed_client_contract"]["success_page_path"], "unknown until observed from authorized run")
        self.assertNotIn("credential", " ".join(data.get("authorization", {}).get("approved_scope", [])))


class TestReadiness(unittest.TestCase):
    def test_ready_transport_does_not_claim_arbitrary_lab_supported(self):
        with patch.object(audit, "run_json", side_effect=[READY_DB, MCP_OK]) as query:
            result = audit.collect(PROJECT, TARGET, check_mcp=True)
        self.assertEqual(query.call_count, 2)
        for call in query.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:2], ["docker", "exec"])
            self.assertNotIn("curl", command)
            self.assertNotIn("challenge.cyberpedia.site", command[:3])
        self.assertEqual(result["burp_transport"]["state"], "reachable")
        self.assertEqual(result["blockers"], ["generic_external_auth_otp_recipe_not_implemented"])
        self.assertFalse(result["governed_execution_ready"])
        self.assertFalse(result["scope"]["external_probe_sent"])

    def test_duplicate_assets_block(self):
        duplicate = {**READY_DB, "assets": [ASSET, dict(ASSET, asset_id=PROJECT)]}
        with patch.object(audit, "run_json", return_value=duplicate):
            result = audit.collect(PROJECT, TARGET, check_mcp=False)
        self.assertIn("exact_target_asset_missing_or_ambiguous", result["blockers"])
        self.assertIn("live_burp_mcp_transport_not_verified", result["blockers"])

    def test_explicit_asset_selection_resolves_duplicate_without_mutation(self):
        duplicate = {**READY_DB, "assets": [ASSET, dict(ASSET, asset_id=PROJECT)]}
        with patch.object(audit, "run_json", return_value=duplicate):
            result = audit.collect(PROJECT, TARGET, check_mcp=False, asset_id=ASSET["asset_id"])
        self.assertNotIn("exact_target_asset_missing_or_ambiguous", result["blockers"])
        self.assertEqual(result["scope"]["asset_id"], ASSET["asset_id"])
        self.assertFalse(result["governed_execution_ready"])

    def test_unknown_asset_selection_fails_closed(self):
        with patch.object(audit, "run_json", return_value=READY_DB):
            result = audit.collect(PROJECT, TARGET, check_mcp=False, asset_id=PROJECT)
        self.assertIn("exact_target_asset_missing_or_ambiguous", result["blockers"])

    def test_missing_provider_is_fail_closed(self):
        missing = {**READY_DB, "provider": {"state": "missing", "decision_ref": None},
                   "approved_operations": []}
        with patch.object(audit, "run_json", side_effect=[missing, MCP_OK]):
            result = audit.collect(PROJECT, TARGET, check_mcp=True)
        self.assertIn("burp_enterprise_provider_not_admissible", result["blockers"])
        self.assertIn("burp_http_operation_not_governed", result["blockers"])

    def test_burp_exception_never_converts_to_ready(self):
        with patch.object(audit, "run_json", side_effect=[READY_DB, RuntimeError("network")]):
            result = audit.collect(PROJECT, TARGET, check_mcp=True)
        self.assertEqual(result["burp_transport"]["state"], "unavailable")
        self.assertFalse(result["governed_execution_ready"])

    def test_report_cannot_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "readiness.json"
            audit.save_new(path, {"ok": True})
            with self.assertRaises(FileExistsError):
                audit.save_new(path, {"ok": False})
            self.assertEqual(__import__("json").loads(path.read_text()), {"ok": True})


if __name__ == "__main__":
    unittest.main()
