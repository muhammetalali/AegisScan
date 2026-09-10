from pathlib import Path


def test_dedicated_reliability_and_domain_integrity_gates_exist():
    root = Path(__file__).parents[1] / '.github' / 'workflows'
    scanner = (root / 'scanner-reliability-reality.yml').read_text(encoding='utf-8')
    domain = (root / 'domain-integrity-reality.yml').read_text(encoding='utf-8')
    for test_name in ('test_scanner_retry_recovery.py', 'test_scanner_redelivery.py', 'test_celery_reliability_contract.py'):
        assert test_name in scanner
    assert 'test_bulk_import_atomicity.py' in domain
    assert 'test_intelligence_lineage.py' in domain
