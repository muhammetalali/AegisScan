from pathlib import Path
import yaml


def test_supply_chain_release_cannot_be_cancelled_by_new_commit():
    path = Path(__file__).parents[1] / '.github' / 'workflows' / 'supply-chain-release.yml'
    with path.open(encoding='utf-8') as f:
        doc = yaml.safe_load(f)
    assert doc['concurrency']['cancel-in-progress'] is False
