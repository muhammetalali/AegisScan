from pathlib import Path

import yaml

root = Path(__file__).parents[1] / '.github' / 'workflows'
for path in sorted(root.glob('*.yml')):
    text = path.read_text(encoding='utf-8')
    workflow = yaml.safe_load(text)
    name = str(workflow.get('name', ''))
    if 'Reality' not in name or workflow.get('concurrency'):
        continue
    print(path)
