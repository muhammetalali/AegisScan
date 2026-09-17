from __future__ import annotations

import json
import unittest

from nuclei_semantic_parity import compare_nuclei_semantics, normalize_nuclei_semantics


def _record(*, matched_at: str, description: str = "Finding reported by Nuclei.") -> str:
    return json.dumps(
        {
            "template-id": "aegis-nuclei-parity",
            "type": "http",
            "matched-at": matched_at,
            "matcher-name": "fixture",
            "info": {
                "name": "Aegis Nuclei Parity Fixture",
                "description": description,
                "severity": "info",
                "reference": ["https://example.invalid/b", "https://example.invalid/a"],
                "classification": {
                    "cve-id": ["CVE-2026-0002", "CVE-2026-0001"],
                    "cwe-id": ["CWE-200"],
                },
            },
        },
        sort_keys=True,
    )


class NucleiSemanticParityTests(unittest.TestCase):
    def test_equivalent_output_ignores_json_order_and_duplicate_findings(self) -> None:
        target = "http://172.32.1.10:8080/aegis-nuclei-parity"
        legacy = _record(matched_at=target)
        candidate_record = json.loads(_record(matched_at=target))
        candidate = "\n".join(
            [
                json.dumps(candidate_record, separators=(",", ":")),
                json.dumps(candidate_record, sort_keys=False),
            ]
        )
        comparison = compare_nuclei_semantics(legacy, candidate)
        self.assertTrue(comparison["equivalent"], comparison)
        self.assertEqual(comparison["candidate"]["raw_record_count"], 2)
        self.assertEqual(comparison["candidate"]["finding_count"], 1)

    def test_finding_relevant_drift_fails_parity(self) -> None:
        target = "http://172.32.1.10:8080/aegis-nuclei-parity"
        comparison = compare_nuclei_semantics(
            _record(matched_at=target, description="legacy"),
            _record(matched_at=target, description="candidate"),
        )
        self.assertFalse(comparison["equivalent"])
        self.assertIn("finding_semantics", comparison["mismatches"])

    def test_malformed_lines_match_production_ignore_semantics(self) -> None:
        target = "http://172.32.1.10:8080/aegis-nuclei-parity"
        normalized = normalize_nuclei_semantics(
            "not-json\n"
            + json.dumps(["not", "an", "object"])
            + "\n"
            + _record(matched_at=target)
        )
        self.assertEqual(normalized["raw_record_count"], 1)
        self.assertEqual(normalized["finding_count"], 1)

    def test_invalid_severity_is_canonicalized_to_info(self) -> None:
        payload = json.loads(_record(matched_at="http://172.32.1.10:8080/aegis-nuclei-parity"))
        payload["info"]["severity"] = "UNKNOWN"
        normalized = normalize_nuclei_semantics(json.dumps(payload))
        self.assertEqual(normalized["observations"][0]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
