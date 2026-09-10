from pathlib import Path
import yaml


def test_explicit_concurrency_groups_are_workflow_scoped():
    root = Path(__file__).parents[1] / '.github' / 'workflows'
    groups = {}
    for path in root.glob('*.yml'):
        with path.open(encoding='utf-8') as f:
            doc = yaml.safe_load(f)
        concurrency = doc.get('concurrency') or {}
        group = concurrency.get('group') if isinstance(concurrency, dict) else None
        if group:
            prefix = str(group).split('${{', 1)[0].rstrip('-')
            assert prefix, path.name
            groups.setdefault(prefix, []).append(path.name)
    collisions = {key: value for key, value in groups.items() if len(value) > 1}
    assert not collisions, collisions
