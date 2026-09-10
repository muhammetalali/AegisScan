from pathlib import Path

import yaml

root = Path(__file__).parents[1] / '.github' / 'workflows'
missing = []
for path in sorted(root.glob('*.yml')):
    with path.open(encoding='utf-8') as handle:
        workflow = yaml.safe_load(handle)
    name = str(workflow.get('name', ''))
    if 'Reality' in name and not workflow.get('concurrency'):
        missing.append(path.name)
if missing:
    raise SystemExit('Reality workflows missing concurrency: ' + ', '.join(missing))
print('All Reality workflows declare concurrency policy')
