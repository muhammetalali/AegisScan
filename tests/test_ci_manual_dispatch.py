from pathlib import Path
import yaml


def test_frontend_manual_dispatch_isolated_from_push_cancellation():
    path = Path(__file__).parents[1] / '.github' / 'workflows' / 'frontend-lock-sync.yml'
    with path.open(encoding='utf-8') as f:
        doc = yaml.safe_load(f)
    group = str(doc['concurrency']['group'])
    assert 'workflow_dispatch' in group
    assert 'github.run_id' in group
