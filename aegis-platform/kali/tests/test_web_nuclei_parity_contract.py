from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "runner" / "web_nuclei_parity_service.py"
SPEC = importlib.util.spec_from_file_location("web_nuclei_parity_service", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class GovernedNucleiParityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        template = Path(self.tempdir.name) / "nuclei-parity.yaml"
        template.write_text("id: parity\n", encoding="utf-8")
        self.config = MODULE.Config(
            auth_token="a" * 64,
            authorization_ref="authorization:parity",
            scope_ref="project:parity:asset:web",
            target="http://172.32.1.10:8080",
            template_path=template,
            template_sha256=MODULE._sha256(template),
        )
        self.payload = {
            "schema_version": 1,
            "execution_ref": "scan:parity:nuclei",
            "authorization_ref": self.config.authorization_ref,
            "scope_ref": self.config.scope_ref,
            "capability_id": "web.nuclei",
            "target": self.config.target,
            "timeout_seconds": 120,
        }

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_valid_payload_binds_authority_scope_target_and_timeout(self) -> None:
        validated = MODULE.validate_payload(dict(self.payload), self.config)
        self.assertEqual(validated["execution_ref"], "scan:parity:nuclei")
        self.assertEqual(validated["timeout_seconds"], 120)

    def test_unknown_field_is_rejected(self) -> None:
        payload = dict(self.payload)
        payload["unexpected"] = "value"
        with self.assertRaisesRegex(MODULE.RequestError, "unknown request fields"):
            MODULE.validate_payload(payload, self.config)

    def test_scope_target_and_authorization_mismatch_fail_closed(self) -> None:
        for field, value in (
            ("authorization_ref", "authorization:other"),
            ("scope_ref", "project:other:asset:web"),
            ("target", "http://172.32.1.11:8080"),
        ):
            with self.subTest(field=field):
                payload = dict(self.payload)
                payload[field] = value
                with self.assertRaises(MODULE.RequestError):
                    MODULE.validate_payload(payload, self.config)

    def test_boolean_or_unbounded_timeout_is_rejected(self) -> None:
        for timeout in (True, 0, 601):
            with self.subTest(timeout=timeout):
                payload = dict(self.payload)
                payload["timeout_seconds"] = timeout
                with self.assertRaises(MODULE.RequestError):
                    MODULE.validate_payload(payload, self.config)

    def test_service_is_loopback_only(self) -> None:
        self.assertEqual(MODULE.LISTEN_HOST, "127.0.0.1")
        self.assertEqual(MODULE.CAPABILITY_ID, "web.nuclei")


if __name__ == "__main__":
    unittest.main()
