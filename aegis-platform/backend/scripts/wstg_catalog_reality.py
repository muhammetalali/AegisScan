"""Verify the shipped catalog against the pinned upstream source, without executing scans."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.wstg_catalog import PACK, UPSTREAM_COMMIT, WSTGCatalog


def verify(upstream: Path) -> dict:
    catalog = WSTGCatalog()
    actual = subprocess.check_output(
        ['git', '-C', str(upstream), 'rev-parse', 'HEAD'], text=True,
    ).strip()
    if actual != UPSTREAM_COMMIT:
        raise ValueError('Upstream checkout is not the pinned WSTG v4.2 commit')
    if subprocess.check_output(['git', '-C', str(upstream), 'status', '--porcelain'], text=True).strip():
        raise ValueError('Upstream checkout must be clean')
    official = {}
    removed = []
    for path in (upstream / 'document/4-Web_Application_Security_Testing').rglob('*.md'):
        content = path.read_text(encoding='utf-8')
        match = re.search(r'\|\s*(WSTG-[A-Z]{4}-\d{2})\s*\|', content[:500])
        if not match:
            continue
        if 'This content has been removed' in content:
            removed.append(str(path.relative_to(upstream)))
            continue
        if match[1] in official:
            raise ValueError('Duplicate upstream identity')
        official[match[1]] = path
    if set(official) != {item.legacy_id for item in catalog.tests}:
        raise ValueError('Catalog differs from upstream official identity set')
    for item in catalog.tests:
        path = official[item.legacy_id]
        if str(path.relative_to(upstream)) != item.source_path:
            raise ValueError(f'Upstream source path mismatch: {item.id}')
        if hashlib.sha256(path.read_bytes()).hexdigest() != item.source_sha256:
            raise ValueError(f'Upstream document fingerprint mismatch: {item.id}')
        if path.read_text(encoding='utf-8').splitlines()[0].removeprefix('# ') != item.title:
            raise ValueError(f'Upstream title mismatch: {item.id}')
        if catalog.resolve(item.legacy_id, version='4.2') != catalog.resolve(item.id):
            raise ValueError(f'Identifier roundtrip mismatch: {item.id}')
    return {
        'proof_scope': 'catalog metadata and identifier contracts only; no security test execution',
        'catalog_valid': True,
        'upstream_commit': actual,
        'official_tests': len(catalog.tests),
        'extensions': len(catalog.extensions),
        'excluded_removed_documents': sorted(removed),
        'pack_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(PACK.glob('*.json'))},
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.upstream), indent=2))
