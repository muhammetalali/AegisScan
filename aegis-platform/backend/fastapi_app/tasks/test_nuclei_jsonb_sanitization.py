from __future__ import annotations

import json

from fastapi_app.tasks.security_scan import _parse_nuclei_findings


def test_nuclei_record_sanitizes_postgresql_incompatible_nul():
    raw = json.dumps({
        "template-id": "binary-response-proof",
        "matched-at": "http://192.0.2.10/",
        "info": {
            "name": "Binary response proof",
            "severity": "info",
        },
        "response": "prefix\x00suffix",
        "nested": {
            "payload": ["safe", "binary\x00value"],
        },
    })

    findings = _parse_nuclei_findings(raw)

    assert len(findings) == 1
    record = findings[0]["record"]

    assert "\x00" not in record["response"]
    assert record["response"] == r"prefix\u0000suffix"
    assert record["nested"]["payload"][1] == r"binary\u0000value"

    encoded = json.dumps(record)
    assert "\x00" not in encoded
