from __future__ import annotations

import json
from pathlib import Path


def test_academy_catalog_baseline_has_only_unverified_counts():
    path = Path(__file__).resolve().parents[2] / "resources/web-labs/academy-topics-baseline.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["topic_count"] == len(doc["topics"]) == 31
    assert doc["lab_count_reference"] == sum(x["count"] for x in doc["topics"]) == 272
    assert len({x["id"] for x in doc["topics"]}) == 31
    assert all(x["state"] == "NOT_TESTED" for x in doc["topics"])
    assert all(x["assessed"] == x["verified"] == 0 for x in doc["topics"])
