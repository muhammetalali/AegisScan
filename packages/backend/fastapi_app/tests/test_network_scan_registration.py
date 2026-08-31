import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")

import django

django.setup()

from fastapi_app.services.engine_adapters import SUPPORTED_REAL_ENGINES
from fastapi_app.tasks.scan_tasks import ENGINE_META


def test_network_engines_are_registered_in_scan_metadata():
    for engine_name in ("network_nmap", "network_masscan"):
        assert engine_name in SUPPORTED_REAL_ENGINES
        assert engine_name in ENGINE_META
        display_name, category, order, timeout = ENGINE_META[engine_name]
        assert display_name
        assert category == "network"
        assert order > 0
        assert timeout > 0
