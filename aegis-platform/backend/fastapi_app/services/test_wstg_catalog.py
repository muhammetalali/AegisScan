"""Catalog boundary tests use real bundled metadata and deliberately invalid variants."""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from pydantic import ValidationError

from fastapi_app.services.wstg_catalog import PACK, WSTGCatalog, WSTGTest


class WSTGCatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = WSTGCatalog()

    def test_all_97_identifiers_roundtrip_with_explicit_version(self):
        self.assertEqual(len(self.catalog.tests), 97)
        for item in self.catalog.tests:
            with self.subTest(identifier=item.id):
                self.assertEqual(self.catalog.resolve(item.id), item)
                self.assertEqual(self.catalog.resolve(item.legacy_id, version='4.2'), item)
                with self.assertRaises(ValueError):
                    self.catalog.resolve(item.legacy_id)

    def test_reject_wrong_version_unknown_and_extension_identifiers(self):
        for identifier in ('WSTG-v41-INFO-01', 'WSTG-v42-INFO-11', 'WSTG-v42-INPV-00',
                           'AEGIS-EXT-CSP', '../tests.json', 'WSTG-v42-INFO-01 ', ''):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                self.catalog.resolve(identifier)
        with self.assertRaises(ValueError):
            self.catalog.resolve('WSTG-v42-INFO-01', version='4.3')

    def test_preserve_every_matrix_row_classification_not_only_totals(self):
        pairs = [(item.id, item.classification) for item in self.catalog.tests]
        digest = hashlib.sha256(json.dumps(pairs, separators=(',', ':')).encode()).hexdigest()
        # Derived from all 97 rows of the user's approved XLSX, not from the pack manifest.
        self.assertEqual(digest, 'c0a5eef1da43030a1a7f97380e71f5b237dbdc8abf6efb4f901061a38d3dd081')

    def test_official_and_extension_namespaces_remain_separate(self):
        self.assertEqual(len(self.catalog.extensions), 8)
        self.assertTrue(all(not item.canonical for item in self.catalog.extensions))
        self.assertTrue(all(item.canonical for item in self.catalog.tests))
        self.assertEqual(self.catalog.resolve('WSTG-v42-INPV-13').title, 'Testing for Format String Injection')

    def test_catalog_has_no_execution_authority_or_result_fields(self):
        record = self.catalog.tests[0].model_dump()
        for field in ('status', 'passed', 'authorized', 'tool', 'command', 'capability_id', 'runner_profile'):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                WSTGTest.model_validate({**record, field: 'untrusted'})
        with self.assertRaises(ValidationError):
            self.catalog.tests[0].title = 'changed'

    def test_reject_identity_source_and_type_corruption(self):
        original = self.catalog.tests[0].model_dump()
        for field, value in [('category', 'CLNT'), ('legacy_id', 'WSTG-INFO-02'),
                             ('canonical', False), ('canonical', 'true'), ('version', 4.2),
                             ('source_path', '../../secret'), ('source_sha256', 'invalid'),
                             ('classification', 'PASSED')]:
            with self.subTest(field=field), self.assertRaises(ValidationError):
                WSTGTest.model_validate({**original, field: value})

    def test_modified_pack_bytes_fail_checksum(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / 'pack'
            shutil.copytree(PACK, pack)
            with (pack / 'tests.json').open('a') as file:
                file.write(' ')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                WSTGCatalog(pack)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / 'pack'
            shutil.copytree(PACK, pack)
            (pack / 'manifest.json').write_text('{"version":"4.2","version":"4.2"}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                WSTGCatalog(pack)

    def test_missing_duplicate_and_wrong_classification_even_with_updated_checksum(self):
        for mutation in ('missing', 'duplicate', 'classification', 'extension'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                pack = Path(tmp) / 'pack'
                shutil.copytree(PACK, pack)
                path = pack / ('extensions.json' if mutation == 'extension' else 'tests.json')
                rows = json.loads(path.read_text())
                if mutation == 'missing':
                    rows.pop()
                elif mutation == 'duplicate':
                    rows[-1] = rows[0]
                elif mutation == 'classification':
                    rows[0]['classification'] = 'AUTO_EXISTING'
                else:
                    rows[0]['id'] = 'WSTG-v42-CLNT-14'
                path.write_text(json.dumps(rows))
                manifest = json.loads((pack / 'manifest.json').read_text())
                manifest['files'][path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
                (pack / 'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    WSTGCatalog(pack)


if __name__ == '__main__':
    unittest.main()
