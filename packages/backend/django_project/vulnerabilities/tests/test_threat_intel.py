from unittest.mock import patch

from django.test import SimpleTestCase

from vulnerabilities.threat_intel import enrich_cve, normalize_cve


class ThreatIntelAdapterTests(SimpleTestCase):
    def test_normalize_cve_rejects_untrusted_identifiers(self):
        self.assertEqual(normalize_cve("cve-2024-1234"), "CVE-2024-1234")
        self.assertIsNone(normalize_cve("https://example.com/CVE-2024-1234"))
        self.assertIsNone(normalize_cve("CVE-foo"))

    @patch("vulnerabilities.threat_intel.fetch_osv")
    @patch("vulnerabilities.threat_intel.fetch_nvd")
    def test_enrichment_aggregates_available_sources(self, fetch_nvd, fetch_osv):
        fetch_nvd.return_value = {
            "source": "NVD", "external_id": "CVE-2024-1234",
            "description": "NVD record", "references": [], "raw": {},
        }
        fetch_osv.return_value = {
            "source": "OSV", "external_id": "CVE-2024-1234",
            "description": "OSV record", "references": [], "raw": {},
        }

        result = enrich_cve("CVE-2024-1234")

        self.assertEqual(result["cve_id"], "CVE-2024-1234")
        self.assertEqual([item["source"] for item in result["sources"]], ["NVD", "OSV"])
        self.assertEqual(result["errors"], [])

    @patch("vulnerabilities.threat_intel.fetch_osv")
    @patch("vulnerabilities.threat_intel.fetch_nvd")
    def test_one_upstream_failure_does_not_drop_other_sources(self, fetch_nvd, fetch_osv):
        fetch_nvd.side_effect = ValueError("bad upstream")
        fetch_osv.return_value = {
            "source": "OSV", "external_id": "CVE-2024-1234",
            "description": "OSV record", "references": [], "raw": {},
        }

        result = enrich_cve("CVE-2024-1234")

        self.assertEqual(len(result["sources"]), 1)
        self.assertEqual(result["sources"][0]["source"], "OSV")
        self.assertEqual(len(result["errors"]), 1)
