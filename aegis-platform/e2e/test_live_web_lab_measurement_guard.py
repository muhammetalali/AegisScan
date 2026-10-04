from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from urllib.parse import urlsplit


MODULE_PATH = Path(__file__).with_name("live_web_lab_measurement.py")
SPEC = importlib.util.spec_from_file_location("live_web_lab_measurement", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class P6IsolationGuardTests(unittest.TestCase):
    def allowed(self, database: str, broker: str, env: dict[str, str]) -> bool:
        return MODULE.p6_environment_allowed(
            urlsplit(database), urlsplit(broker), env
        )

    def test_dedicated_p6_context_is_allowed(self):
        self.assertTrue(
            self.allowed(
                "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6",
                "redis://aegis-burp-p3-redis:6379/2",
                {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
            )
        )

    def test_p4_context_cannot_authorize_p6_harness(self):
        self.assertFalse(
            self.allowed(
                "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p4",
                "redis://aegis-burp-p3-redis:6379/1",
                {"AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1"},
            )
        )

    def test_p4_flag_and_p6_flag_cannot_be_combined(self):
        self.assertFalse(
            self.allowed(
                "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6",
                "redis://aegis-burp-p3-redis:6379/2",
                {
                    "AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1",
                    "AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1",
                },
            )
        )

    def test_production_or_arbitrary_hosts_are_rejected(self):
        self.assertFalse(
            self.allowed(
                "postgresql://u:p@prod-db:5432/aegis",
                "redis://prod-redis:6379/0",
                {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
            )
        )


if __name__ == "__main__":
    unittest.main()
