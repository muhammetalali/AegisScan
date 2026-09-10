from pathlib import Path
import yaml
root = Path(__file__).parents[1] / '.github' / 'workflows'
for path in sorted(root.glob('*.yml')):
    with path.open(encoding='utf-8') as f:
        doc = yaml.safe_load(f)
    if 'Reality' in str(doc.get('name', '')):
        print(f"{path.name}: {'yes' if doc.get('concurrency') else 'NO'}")
