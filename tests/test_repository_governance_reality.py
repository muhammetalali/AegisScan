#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "ci" / "repository_governance_reality.py"
SPEC = importlib.util.spec_from_file_location("repository_governance_reality", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BypassEvidenceTests(unittest.TestCase):
    def test_permission_limited_detail_is_classified_without_false_failure(self) -> None:
        evidence = MODULE._bypass_evidence({"name": "ruleset"})
        self.assertEqual(evidence["visibility"], "permission_limited")
        self.assertIsNone(evidence["count"])
        self.assertTrue(evidence["admin_verification_required"])

    def test_visible_empty_bypass_list_is_proven(self) -> None:
        evidence = MODULE._bypass_evidence(
            {"bypass_actors": [], "current_user_can_bypass": "never"}
        )
        self.assertEqual(evidence["visibility"], "visible")
        self.assertEqual(evidence["count"], 0)
        self.assertFalse(evidence["admin_verification_required"])

    def test_visible_bypass_actor_fails_closed(self) -> None:
        with self.assertRaises(MODULE.GovernanceError):
            MODULE._bypass_evidence(
                {
                    "bypass_actors": [{"actor_id": 1, "actor_type": "RepositoryRole"}],
                    "current_user_can_bypass": "never",
                }
            )

    def test_workflow_identity_bypass_fails_closed_even_when_actor_list_is_hidden(self) -> None:
        with self.assertRaises(MODULE.GovernanceError):
            MODULE._bypass_evidence({"current_user_can_bypass": "always"})


if __name__ == "__main__":
    unittest.main()
