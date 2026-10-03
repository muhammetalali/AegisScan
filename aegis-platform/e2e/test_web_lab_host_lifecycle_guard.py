from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "web_lab_host_lifecycle.py"
SPEC = importlib.util.spec_from_file_location("web_lab_host_lifecycle", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class HostLifecycleControlGuardTests(unittest.TestCase):
    def test_only_sealed_control_containers_are_allowed(self):
        for name in (
            "aegis-django",
            "aegis-burp-p5-control",
            "aegis-burp-p6-control",
        ):
            self.assertIsNotNone(MODULE.CONTROL_RE.fullmatch(name), name)

        for name in (
            "aegis-burp-p7-control",
            "aegis-burp-p6-control-extra",
            "other-container",
            "",
        ):
            self.assertIsNone(MODULE.CONTROL_RE.fullmatch(name), name)

    def test_p6_control_does_not_broaden_target_or_network_names(self):
        self.assertIsNotNone(
            MODULE.NETWORK_RE.fullmatch("aegis-burp-p2-egress")
        )
        self.assertIsNone(MODULE.NETWORK_RE.fullmatch("bridge"))
        self.assertIsNone(MODULE.CONTAINER_RE.fullmatch("aegis-burp-p6-control"))


if __name__ == "__main__":
    unittest.main()
