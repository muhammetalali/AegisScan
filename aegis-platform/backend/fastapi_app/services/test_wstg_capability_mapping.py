import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from pydantic import ValidationError

from fastapi_app.services.wstg_capability_mapping import (
    EXPECTED_GAPS,
    CapabilityRequirement,
    WSTGCapabilityMapping,
)
from fastapi_app.services.wstg_catalog import PACK


class WSTGCapabilityMappingTests(unittest.TestCase):
    def setUp(self):
        self.mapping = WSTGCapabilityMapping()

    def test_covers_exactly_all_97_official_tests(self):
        self.assertEqual(len(self.mapping.mappings), 97)
        self.assertEqual(len(self.mapping.requirements), 97)
        self.assertEqual(
            {item.wstg_id for item in self.mapping.mappings},
            {item.id for item in self.mapping.catalog.tests},
        )

    def test_wstg_records_reference_semantic_ids_not_tools_or_runtime(self):
        banned = {
            'nmap', 'masscan', 'rustscan', 'nuclei', 'semgrep', 'httpx', 'katana',
            'ffuf', 'feroxbuster', 'gobuster', 'dirb', 'nikto', 'wafw00f',
            'amass', 'subfinder',
        }
        for mapping in self.mapping.mappings:
            dumped = mapping.model_dump()
            self.assertEqual(set(dumped), {'wstg_id', 'required_capability_ids'})
            for requirement_id in mapping.required_capability_ids:
                tokens = set(requirement_id.replace('.', '-').split('-'))
                self.assertFalse(tokens & banned)

    def test_existing_registry_bindings_resolve_authoritative_registry(self):
        registry = [
            binding.ref
            for requirement in self.mapping.requirements
            for binding in requirement.provider_bindings
            if binding.kind == 'registry_capability'
        ]
        self.assertTrue(registry)
        from fastapi_app.services.capability_registry import get_capability
        for capability_id in sorted(set(registry)):
            with self.subTest(capability_id=capability_id):
                self.assertEqual(get_capability(capability_id).id, capability_id)

    def test_only_five_approved_native_gaps_exist(self):
        actual = {}
        for test in self.mapping.catalog.tests:
            if test.classification != 'GAP_NATIVE_SMALL':
                continue
            requirement = self.mapping.resolve(test.id)[0]
            actual[test.id] = [
                item.ref for item in requirement.provider_bindings if item.kind == 'planned_native'
            ][0]
        self.assertEqual(actual, EXPECTED_GAPS)

    def test_manual_rows_remain_governed_and_conditional_row_stays_conditional(self):
        for test in self.mapping.catalog.tests:
            requirement = self.mapping.resolve(test.id)[0]
            if test.classification == 'MANUAL_GOVERNED':
                self.assertEqual(requirement.availability, 'governed_manual')
                self.assertTrue(any(x.kind == 'governed_service' for x in requirement.provider_bindings))
            if test.classification == 'CONDITIONAL_NA':
                self.assertEqual(test.id, 'WSTG-v42-CLNT-08')
                self.assertEqual(requirement.availability, 'conditional')

    def test_requirement_contract_rejects_execution_authority_fields(self):
        row = self.mapping.requirements[0].model_dump()
        for field in ('tool', 'binary', 'command', 'runner_profile', 'authorized', 'status', 'passed'):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                CapabilityRequirement.model_validate({**row, field: 'untrusted'})

    def test_checksum_and_unknown_registry_provider_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / 'pack'
            shutil.copytree(PACK, pack)
            requirements_path = pack / 'capability_requirements.json'
            rows = json.loads(requirements_path.read_text())
            rows[0]['provider_bindings'][0] = {
                'kind': 'registry_capability',
                'ref': 'web.nonexistent-provider',
            }
            requirements_path.write_text(json.dumps(rows))
            manifest_path = pack / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            manifest['capability_mapping_files']['capability_requirements.json'] = hashlib.sha256(
                requirements_path.read_bytes()
            ).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                WSTGCapabilityMapping(pack)

        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / 'pack'
            shutil.copytree(PACK, pack)
            with (pack / 'mappings.json').open('a') as handle:
                handle.write(' ')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                WSTGCapabilityMapping(pack)


if __name__ == '__main__':
    unittest.main()
