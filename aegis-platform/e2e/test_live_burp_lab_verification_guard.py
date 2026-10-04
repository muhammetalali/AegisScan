from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from urllib.parse import urlsplit


MODULE_PATH = Path(__file__).with_name("live_burp_lab_verification.py")
SPEC = importlib.util.spec_from_file_location("live_burp_lab_verification", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)

P6_MODULE_PATH = Path(__file__).with_name("live_web_lab_measurement.py")
P6_SPEC = importlib.util.spec_from_file_location("live_web_lab_measurement", P6_MODULE_PATH)
P6_MODULE = importlib.util.module_from_spec(P6_SPEC)
assert P6_SPEC and P6_SPEC.loader
P6_SPEC.loader.exec_module(P6_MODULE)


class IsolationGuardTests(unittest.TestCase):
    def allowed(self, database: str, broker: str, env: dict[str, str]) -> bool:
        return MODULE.isolated_environment_allowed(
            urlsplit(database), urlsplit(broker), env
        )

    def test_legacy_p4_context_remains_allowed(self):
        self.assertTrue(
            self.allowed(
                "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p4",
                "redis://aegis-burp-p3-redis:6379/1",
                {"AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1"},
            )
        )

    def test_p6_context_requires_distinct_db_broker_and_flag(self):
        self.assertTrue(
            self.allowed(
                "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6",
                "redis://aegis-burp-p3-redis:6379/2",
                {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
            )
        )
        self.assertFalse(
            self.allowed(
                "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6",
                "redis://aegis-burp-p3-redis:6379/1",
                {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
            )
        )

    def test_production_or_arbitrary_hosts_are_rejected(self):
        self.assertFalse(
            self.allowed(
                "postgresql://u:p@prod-db:5432/aegis",
                "redis://prod-redis:6379/0",
                {
                    "AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1",
                    "AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1",
                },
            )
        )

    def test_p4_flag_cannot_authorize_p6_and_p6_flag_cannot_authorize_p4(self):
        p4_db = "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p4"
        p6_db = "postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6"
        p4_broker = "redis://aegis-burp-p3-redis:6379/1"
        p6_broker = "redis://aegis-burp-p3-redis:6379/2"
        self.assertFalse(
            self.allowed(
                p6_db,
                p6_broker,
                {"AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1"},
            )
        )
        self.assertFalse(
            self.allowed(
                p4_db,
                p4_broker,
                {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
            )
        )

    def test_p6_harness_accepts_only_dedicated_measurement_namespace(self):
        good = P6_MODULE.p6_environment_allowed(
            urlsplit("postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6"),
            urlsplit("redis://aegis-burp-p3-redis:6379/2"),
            {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
        )
        self.assertTrue(good)
        self.assertFalse(P6_MODULE.p6_environment_allowed(
            urlsplit("postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p4"),
            urlsplit("redis://aegis-burp-p3-redis:6379/1"),
            {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
        ))

    def test_p6_harness_rejects_p4_flag_or_production(self):
        self.assertFalse(P6_MODULE.p6_environment_allowed(
            urlsplit("postgresql://u:p@aegis-burp-p3-postgres:5432/burp_p6"),
            urlsplit("redis://aegis-burp-p3-redis:6379/2"),
            {
                "AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1",
                "AEGIS_ISOLATED_BURP_LAB_VERIFICATION_PROOF": "1",
            },
        ))
        self.assertFalse(P6_MODULE.p6_environment_allowed(
            urlsplit("postgresql://u:p@prod-db:5432/aegis"),
            urlsplit("redis://prod-redis:6379/0"),
            {"AEGIS_ISOLATED_WEB_LAB_MEASUREMENT_PROOF": "1"},
        ))


if __name__ == "__main__":
    unittest.main()
