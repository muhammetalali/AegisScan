#!/usr/bin/env python3
"""Snapshot PortSwigger's public All Labs index; no lab traffic or cookies."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

SOURCE = 'https://portswigger.net/web-security/all-labs'
DEST = Path(__file__).resolve().parents[1] / 'resources/web-labs/portswigger-all-labs.v1.json'
WIDGET = re.compile(r'^[A-F0-9]{64}$')


class LabIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.category = None
        self.rows = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'h2' and attrs.get('id'):
            self.category = attrs['id']
        if tag == 'div' and attrs.get('widget-id') == 'academy-labstatus':
            lab_id = attrs.get('widget-lab-id', '')
            if not self.category or not WIDGET.fullmatch(lab_id):
                raise ValueError('Invalid category or PortSwigger lab widget ID')
            self.rows.append((self.category, lab_id))


def main() -> int:
    request = urllib.request.Request(SOURCE, headers={'User-Agent': 'AegisScan-CatalogSync/1.0'})
    with urllib.request.urlopen(request, timeout=25) as response:
        if response.status != 200:
            raise RuntimeError(f'Catalog HTTP status {response.status}')
        source = response.read(2_000_000)
    parsed = LabIndex()
    parsed.feed(source.decode('utf-8', errors='replace'))
    unique = {lab_id for _, lab_id in parsed.rows}
    if not 250 <= len(parsed.rows) <= 450 or len(unique) != len(parsed.rows):
        raise RuntimeError('Catalog count or uniqueness unexpectedly changed; manual review required')
    category_counts = Counter(category for category, _ in parsed.rows)
    seen = Counter()
    labs = []
    for ordinal, (category, lab_id) in enumerate(parsed.rows, start=1):
        seen[category] += 1
        labs.append({
            'ordinal': ordinal,
            'category': category,
            'category_ordinal': seen[category],
            'widget_lab_id': lab_id,
        })
    payload = {
        'schema': 'aegisscan.portswigger-academy-catalog.v1',
        'source_url': SOURCE,
        'retrieved_at_utc': datetime.now(timezone.utc).isoformat(),
        'source_html_sha256': hashlib.sha256(source).hexdigest(),
        'category_count': len(category_counts),
        'lab_count': len(labs),
        'categories': [{'slug': c, 'count': n} for c, n in category_counts.items()],
        'labs': labs,
    }
    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'path': str(DEST), 'count': len(labs), 'categories': len(category_counts)}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
