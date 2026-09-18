from __future__ import annotations

import json
import unittest

from semgrep_semantic_parity import (
    compare_semgrep_semantics,
    normalize_semgrep_semantics,
)


def _payload(*, path: str = "/workspace/source/app.py", message: str = "Aegis Semgrep parity fixture") -> str:
    return json.dumps(
        {
            "results": [
                {
                    "check_id": "aegis.semgrep.parity.eval",
                    "path": path,
                    "start": {"line": 2, "col": 12, "offset": 31},
                    "end": {"line": 2, "col": 28, "offset": 47},
                    "extra": {
                        "message": message,
                        "severity": "WARNING",
                    },
                }
            ],
            "errors": [],
        },
        sort_keys=True,
    )


class SemgrepSemanticParityTests(unittest.TestCase):
    def test_equivalent_payloads_ignore_json_key_order(self) -> None:
        legacy = _payload()
        candidate = json.dumps(json.loads(_payload()), sort_keys=False)
        comparison = compare_semgrep_semantics(legacy, candidate)
        self.assertTrue(comparison["equivalent"], comparison)
        self.assertEqual(comparison["legacy"]["finding_count"], 1)
        self.assertEqual(comparison["candidate"]["finding_count"], 1)

    def test_finding_relevant_drift_fails_parity(self) -> None:
        comparison = compare_semgrep_semantics(
            _payload(message="legacy"),
            _payload(message="candidate"),
        )
        self.assertFalse(comparison["equivalent"])
        self.assertIn("finding_semantics", comparison["mismatches"])

    def test_production_severity_mapping_is_preserved(self) -> None:
        payload = json.loads(_payload())
        payload["results"][0]["extra"]["severity"] = "ERROR"
        normalized = normalize_semgrep_semantics(json.dumps(payload))
        self.assertEqual(normalized["observations"][0]["severity"], "high")

    def test_invalid_json_matches_empty_production_projection(self) -> None:
        normalized = normalize_semgrep_semantics("not-json")
        self.assertEqual(normalized["finding_count"], 0)
        self.assertEqual(normalized["observations"], [])


if __name__ == "__main__":
    unittest.main()
