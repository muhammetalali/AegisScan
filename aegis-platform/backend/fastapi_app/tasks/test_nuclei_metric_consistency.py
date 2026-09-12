from types import SimpleNamespace

from fastapi_app.tasks.security_scan import _unique_findings_by_id


def test_nuclei_unique_finding_metric_preserves_first_seen_order():
    findings = [
        SimpleNamespace(id="finding-a"),
        SimpleNamespace(id="finding-a"),
        SimpleNamespace(id="finding-b"),
        SimpleNamespace(id="finding-b"),
        SimpleNamespace(id="finding-c"),
    ]

    unique = _unique_findings_by_id(findings)

    assert len(findings) == 5
    assert len(unique) == 3
    assert [str(item.id) for item in unique] == [
        "finding-a",
        "finding-b",
        "finding-c",
    ]
