import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")

import django

django.setup()

from django.test import SimpleTestCase

from fastapi_app.services.engine_adapters import SUPPORTED_REAL_ENGINES
from fastapi_app.tasks.scan_tasks import ENGINE_META


class NetworkEngineRegistrationTests(SimpleTestCase):
    def test_network_engines_are_registered_in_scan_metadata(self):
        for engine_name in ("network_nmap", "network_masscan"):
            with self.subTest(engine=engine_name):
                self.assertIn(engine_name, SUPPORTED_REAL_ENGINES)
                self.assertIn(engine_name, ENGINE_META)
                display_name, category, order, timeout = ENGINE_META[engine_name]
                self.assertTrue(display_name)
                self.assertEqual(category, "recon")
                self.assertGreater(order, 0)
                self.assertGreater(timeout, 0)
