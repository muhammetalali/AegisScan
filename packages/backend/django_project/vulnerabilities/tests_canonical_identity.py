from types import SimpleNamespace

from django.test import SimpleTestCase

from vulnerabilities.identity import (
    build_canonical_identity,
    canonical_rule_key,
    normalize_target,
)


class CanonicalIdentityTests(SimpleTestCase):
    def test_hsts_title_aliases_share_rule_key(self):
        self.assertEqual(
            canonical_rule_key("HTTPS response lacks Strict-Transport-Security", "transport_security"),
            "missing-hsts",
        )
        self.assertEqual(
            canonical_rule_key("Missing Strict-Transport-Security", "security_headers"),
            "missing-hsts",
        )

    def test_target_normalization_removes_fragment_and_default_port(self):
        self.assertEqual(
            normalize_target("HTTPS://Platform.CyberPedia.Site:443/#login"),
            "https://platform.cyberpedia.site/",
        )

    def test_hsts_findings_from_different_engines_get_same_fingerprint(self):
        common = {
            "project_id": "project-1",
            "asset_id": None,
            "url": "",
            "method": "",
            "parameter": "",
            "file_path": "",
            "function_name": "",
            "cwe_id": "",
            "raw_data": {"url": "https://platform.cyberpedia.site", "asset": "platform.cyberpedia.site"},
        }
        first = SimpleNamespace(
            **common,
            title="HTTPS response lacks Strict-Transport-Security",
            category="transport_security",
        )
        second = SimpleNamespace(
            **common,
            title="Missing Strict-Transport-Security",
            category="security_headers",
        )

        first_identity = build_canonical_identity(first)
        second_identity = build_canonical_identity(second)

        self.assertEqual(first_identity[0], second_identity[0])
        self.assertEqual(first_identity[1], "missing-hsts")
        self.assertEqual(second_identity[1], "missing-hsts")
