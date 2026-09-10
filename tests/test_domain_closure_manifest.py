from pathlib import Path


def test_domain_contract_runs_current_head_closure_proofs():
    text = (Path(__file__).parents[1] / '.github' / 'workflows' / 'domain-contract-reality.yml').read_text(encoding='utf-8')
    assert 'test_bulk_import_atomicity.py' in text
    assert 'test_intelligence_lineage.py' in text
    assert 'test_scanner_retry_recovery.py' in text
    assert 'test_scanner_redelivery.py' in text
    assert 'test_celery_reliability_contract.py' in text
