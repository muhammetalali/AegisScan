"""Read-only WSTG methodology metadata. This module never authorizes or runs tests."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


PACK = Path(__file__).resolve().parents[2] / 'resources/methodologies/wstg/v4.2'
CATEGORY_COUNTS = {
    'INFO': 10, 'CONF': 11, 'IDNT': 5, 'ATHN': 10, 'ATHZ': 4, 'SESS': 9,
    'INPV': 19, 'ERRH': 2, 'CRYP': 4, 'BUSL': 9, 'CLNT': 13, 'APIT': 1,
}
CLASSIFICATION_COUNTS = {
    'AUTO_EXISTING': 25, 'ASSISTED_EXISTING': 46, 'MANUAL_GOVERNED': 21,
    'GAP_NATIVE_SMALL': 4, 'CONDITIONAL_NA': 1,
}
UPSTREAM_COMMIT = 'dd33419e10edb22b78d89325a6c2aad9f184e3a2'
Classification = Literal[
    'AUTO_EXISTING', 'ASSISTED_EXISTING', 'MANUAL_GOVERNED',
    'GAP_NATIVE_SMALL', 'CONDITIONAL_NA',
]


class CatalogModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)


class WSTGTest(CatalogModel):
    id: str
    legacy_id: str
    version: Literal['4.2']
    category: str
    title: str = Field(min_length=1, max_length=256)
    canonical: Literal[True]
    classification: Classification
    source_path: str
    source_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')

    @model_validator(mode='after')
    def validate_identity(self):
        match = re.fullmatch(r'WSTG-v42-([A-Z]{4})-([0-9]{2})', self.id)
        if not match or match[1] not in CATEGORY_COUNTS:
            raise ValueError('Unknown WSTG v4.2 identity')
        if not 1 <= int(match[2]) <= CATEGORY_COUNTS[match[1]]:
            raise ValueError('WSTG test number outside canonical category')
        if self.category != match[1] or self.legacy_id != self.id.replace('-v42', ''):
            raise ValueError('WSTG identity/category/version mismatch')
        path = Path(self.source_path)
        if (path.is_absolute() or '..' in path.parts or '\\' in self.source_path
                or not self.source_path.startswith('document/4-Web_Application_Security_Testing/')
                or path.suffix != '.md'):
            raise ValueError('Invalid upstream source path')
        return self

    @property
    def source_url(self) -> str:
        return f'https://github.com/OWASP/wstg/blob/{UPSTREAM_COMMIT}/{self.source_path}'


class WSTGExtension(CatalogModel):
    id: str = Field(pattern=r'^AEGIS-EXT-[A-Z]+(?:-[A-Z]+)*$')
    version: Literal['1.0']
    title: str = Field(min_length=1, max_length=256)
    canonical: Literal[False]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate catalog JSON key: {key}')
        result[key] = value
    return result


def _read(path: Path):
    raw = path.read_bytes()
    if len(raw) > 256_000:
        raise ValueError('Catalog file exceeds size limit')
    return raw, json.loads(raw, object_pairs_hook=_unique_object)


class WSTGCatalog:
    """Validated bundled metadata; legacy IDs require an explicit methodology version."""

    def __init__(self, pack: Path = PACK):
        _, manifest = _read(pack / 'manifest.json')
        if (manifest.get('schema_version') != '1.0' or manifest.get('version') != '4.2'
                or manifest.get('methodology') != 'WSTG'
                or manifest.get('official_count') != 97
                or manifest.get('category_counts') != CATEGORY_COUNTS
                or manifest.get('classification_counts') != CLASSIFICATION_COUNTS
                or manifest.get('upstream_commit') != UPSTREAM_COMMIT
                or manifest.get('license') != 'CC-BY-SA-4.0'):
            raise ValueError('Unsupported or inconsistent WSTG manifest')
        digests = manifest.get('files')
        if not isinstance(digests, dict) or set(digests) != {'tests.json', 'extensions.json'}:
            raise ValueError('Unexpected WSTG pack files')
        payloads = {}
        for name, digest in digests.items():
            raw, data = _read(pack / name)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError(f'Catalog checksum mismatch: {name}')
            if not isinstance(data, list):
                raise ValueError('Catalog records must be arrays')
            payloads[name] = data
        self.tests = tuple(WSTGTest.model_validate(row) for row in payloads['tests.json'])
        self.extensions = tuple(WSTGExtension.model_validate(row) for row in payloads['extensions.json'])
        expected = {
            f'WSTG-v42-{category}-{number:02d}'
            for category, count in CATEGORY_COUNTS.items() for number in range(1, count + 1)
        }
        if len(self.tests) != 97 or {item.id for item in self.tests} != expected:
            raise ValueError('Missing, duplicate or unexpected WSTG tests')
        if Counter(item.classification for item in self.tests) != CLASSIFICATION_COUNTS:
            raise ValueError('Execution classification baseline changed')
        extension_ids = {
            'AEGIS-EXT-CSP', 'AEGIS-EXT-PATH-CONFUSION', 'AEGIS-EXT-MFA', 'AEGIS-EXT-OAUTH',
            'AEGIS-EXT-JWT', 'AEGIS-EXT-MASS-ASSIGNMENT', 'AEGIS-EXT-PAYMENT',
            'AEGIS-EXT-REVERSE-TABNABBING',
        }
        if len(self.extensions) != 8 or {item.id for item in self.extensions} != extension_ids:
            raise ValueError('Missing, duplicate or unexpected Aegis extensions')

    def resolve(self, identifier: str, *, version: str | None = None) -> WSTGTest:
        if version is not None and version != '4.2':
            raise ValueError('Unsupported WSTG version')
        if re.fullmatch(r'WSTG-[A-Z]{4}-[0-9]{2}', identifier):
            if version is None:
                raise ValueError('Legacy WSTG identifiers require explicit version')
            identifier = identifier.replace('WSTG-', 'WSTG-v42-', 1)
        for item in self.tests:
            if item.id == identifier:
                return item
        raise ValueError('Unknown canonical WSTG identifier')
