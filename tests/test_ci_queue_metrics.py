import json
import subprocess
import sys
from pathlib import Path


def test_queue_metrics_counts_states():
    script = Path(__file__).parents[1] / 'scripts' / 'ci_queue_metrics.py'
    payload = {'workflow_runs': [{'status': 'queued'}, {'status': 'queued'}, {'status': 'in_progress'}]}
    result = subprocess.run([sys.executable, str(script)], input=json.dumps(payload), text=True, capture_output=True, check=True)
    assert json.loads(result.stdout) == {'in_progress': 1, 'queued': 2}
