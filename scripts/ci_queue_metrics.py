import json
import sys

payload = json.load(sys.stdin)
runs = payload.get('workflow_runs', [])
counts = {}
for run in runs:
    status = run.get('status', 'unknown')
    counts[status] = counts.get(status, 0) + 1
print(json.dumps(counts, sort_keys=True))
