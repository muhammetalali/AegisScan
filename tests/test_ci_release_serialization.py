from pathlib import Path
import yaml


def test_release_has_stable_serialization_group():
    path = Path(__file__).parents[1] / '.github' / 'workflows' / 'supply-chain-release.yml'
    with path.open(encoding='utf-8') as f:
        doc = yaml.safe_load(f)
    group = str(doc['concurrency']['group'])
    assert group.startswith('supply-chain-')
    assert '${{ github.ref }}' in group
    assert doc['concurrency']['cancel-in-progress'] is False
