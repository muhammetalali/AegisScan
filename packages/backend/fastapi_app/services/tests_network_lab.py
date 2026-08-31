from __future__ import annotations

from django.test import SimpleTestCase

from fastapi_app.services.engine_adapters import SUPPORTED_REAL_ENGINES
from fastapi_app.services.network_lab_executor import _authorized_target


class NetworkLabAdapterTests(SimpleTestCase):
    def test_network_engines_are_real_registered(self):
        self.assertIn("network_nmap", SUPPORTED_REAL_ENGINES)
        self.assertIn("network_masscan", SUPPORTED_REAL_ENGINES)

    def test_exact_allowlist_and_explicit_authorization_are_required(self):
        self.assertTrue(_authorized_target("127.0.0.1", {"authorized": True, "lab_target_allowlist": ["127.0.0.1"]}))
        self.assertFalse(_authorized_target("127.0.0.2", {"authorized": True, "lab_target_allowlist": ["127.0.0.1"]}))
        self.assertFalse(_authorized_target("127.0.0.1", {"authorized": False, "lab_target_allowlist": ["127.0.0.1"]}))
        self.assertFalse(_authorized_target("127.0.0.1", {"authorized": True}))
