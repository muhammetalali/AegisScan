from __future__ import annotations

import asyncio
import json
import re
from collections import Counter

import pytest
from fastapi import HTTPException

from fastapi_app.routers.web_labs import ACADEMY_CATALOG_PATH, academy_catalog


def test_official_snapshot_unique_and_ordered():
    catalog = json.loads(ACADEMY_CATALOG_PATH.read_text(encoding='utf-8'))
    assert catalog['schema'] == 'aegisscan.portswigger-academy-catalog.v1'
    assert catalog['source_url'] == 'https://portswigger.net/web-security/all-labs'
    assert re.fullmatch(r'[a-f0-9]{64}', catalog['source_html_sha256'])
    rows = catalog['labs']
    assert len(rows) == catalog['lab_count'] == 273
    assert len(catalog['categories']) == catalog['category_count'] == 31
    assert [r['ordinal'] for r in rows] == list(range(1, 274))
    assert len({r['widget_lab_id'] for r in rows}) == len(rows)
    assert all(re.fullmatch(r'[A-F0-9]{64}', r['widget_lab_id']) for r in rows)
    counts = Counter(row['category'] for row in rows)
    assert [(r['slug'], r['count']) for r in catalog['categories']] == list(counts.items())
    for slug, count in counts.items():
        assert [r['category_ordinal'] for r in rows if r['category'] == slug] == list(range(1, count+1))


def test_catalog_read_only_pagination_and_category():
    result = asyncio.run(academy_catalog(category='sql-injection', offset=0, limit=2, user={'user_id': '15'}))
    assert result.contract_version == 'aegis.academy-catalog.v1'
    assert result.matching_count == 18
    assert len(result.items) == 2
    assert [item.ordinal for item in result.items] == [1, 2]
    assert all(item.category == 'sql-injection' for item in result.items)


def test_catalog_rejects_unknown_category_without_scanning():
    with pytest.raises(HTTPException) as caught:
        asyncio.run(academy_catalog(category='not-a-category', offset=0, limit=10, user={'user_id': '15'}))
    assert caught.value.status_code == 404


def test_catalog_requires_authenticated_identity():
    with pytest.raises(HTTPException) as caught:
        asyncio.run(academy_catalog(category=None, offset=0, limit=10, user={}))
    assert caught.value.status_code == 401


def test_catalog_last_page_and_no_fabricated_completion():
    result = asyncio.run(academy_catalog(category=None, offset=270, limit=100, user={'user_id': '15'}))
    assert result.matching_count == 273
    assert [item.ordinal for item in result.items] == [271, 272, 273]
    assert all(not hasattr(item, 'solved') for item in result.items)
