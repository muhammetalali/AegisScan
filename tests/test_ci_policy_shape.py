from pathlib import Path
import yaml


def test_cancelled_workflows_are_scoped_to_pr_or_ref():
    root = Path(__file__).parents[1] / '.github' / 'workflows'
    for path in root.glob('*.yml'):
        with path.open(encoding='utf-8') as f:
            doc = yaml.safe_load(f)
        concurrency = doc.get('concurrency') or {}
        if not isinstance(concurrency, dict) or concurrency.get('cancel-in-progress') is not True:
            continue
        group = str(concurrency.get('group', ''))
        assert 'pull_request.number' in group or 'github.ref' in group, path.name
