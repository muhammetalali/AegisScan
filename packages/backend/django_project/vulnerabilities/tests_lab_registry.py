from __future__ import annotations

from django.test import SimpleTestCase

from fastapi_app.services.lab_registry import capability_detail, lab_detail, lab_readiness, lab_snapshot


class LabRegistryTests(SimpleTestCase):
    def test_network_lab_is_explicit_and_not_default_enabled(self):
        lab = lab_detail("network-lab")
        self.assertIsNotNone(lab)
        assert lab is not None
        self.assertFalse(lab["isolation"]["default_enabled"])
        self.assertTrue(lab["authorization"]["required"])
        self.assertTrue(lab["authorization"]["target_allowlist_required"])
        self.assertFalse(lab["evidence"]["synthetic_results_allowed"])

    def test_network_capabilities_have_evidence_contracts(self):
        for capability_id in ("distribution.kali", "network.nmap", "network.masscan"):
            capability = capability_detail(capability_id)
            self.assertIsNotNone(capability)
            assert capability is not None
            self.assertTrue(capability["authorization_required"])
            self.assertTrue(capability["sandbox_required"])
        self.assertTrue(capability_detail("network.nmap")["evidence"])
        self.assertTrue(capability_detail("network.masscan")["evidence"])

    def test_readiness_does_not_claim_network_tool_execution_is_ready(self):
        readiness = lab_readiness("network-lab")
        self.assertEqual(readiness["readiness"], "ready-to-provision")
        self.assertFalse(readiness["capabilities"]["network.nmap"]["ready"])
        self.assertFalse(readiness["capabilities"]["network.masscan"]["ready"])

    def test_snapshot_forbids_synthetic_results(self):
        snapshot = lab_snapshot()
        self.assertFalse(snapshot["policy"]["synthetic_results"])
        self.assertTrue(snapshot["policy"]["execution_provenance_required"])
