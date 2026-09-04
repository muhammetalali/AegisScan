from __future__ import annotations

from fastapi_app.services.evidence_identity import evidence_id


def test_evidence_identity_is_stable_across_task_redelivery():
    first = evidence_id('scan', 'scan-1', 'nmap', 'scanner_output')
    second = evidence_id('scan', 'scan-1', 'nmap', 'scanner_output')
    assert first == second


def test_evidence_identity_separates_operations_and_findings():
    scanner = evidence_id('scan', 'scan-1', 'nmap', 'scanner_output')
    finding_a = evidence_id('scan', 'scan-1', 'nmap', 'scanner_output', 'finding-a')
    finding_b = evidence_id('scan', 'scan-1', 'nmap', 'scanner_output', 'finding-b')
    validation = evidence_id('validation', 'scan-1', 'nmap', 'validation_output', 'finding-a')
    assert len({scanner, finding_a, finding_b, validation}) == 4
