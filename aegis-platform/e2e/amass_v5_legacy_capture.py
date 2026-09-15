#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

from fastapi_app.services.native_tool_runtime import run_native_tool


def _digest(path: str) -> str:
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main() -> int:
    capability = os.environ.get('AEGIS_AMASS_CAPABILITY', 'recon.amass')
    target = os.environ.get('AEGIS_AMASS_TARGET', 'parity.test')
    artifact_dir = Path(os.environ.get('AEGIS_ARTIFACT_DIR', '/artifacts'))
    artifact_dir.mkdir(parents=True, exist_ok=True)

    result = run_native_tool(capability, target, {'timeout_minutes': 1})
    if result.exit_code != 0:
        raise SystemExit(
            f'legacy Amass failed: exit={result.exit_code} stderr={result.stderr[:4000]}'
        )

    wrapper_version = subprocess.check_output(
        ['/usr/local/bin/amass', '-version'], text=True, stderr=subprocess.STDOUT
    ).strip()
    raw_version = subprocess.check_output(
        ['/usr/local/libexec/amass-real', '-version'], text=True, stderr=subprocess.STDOUT
    ).strip()
    if '5.1.1' not in wrapper_version or '5.1.1' not in raw_version:
        raise AssertionError((wrapper_version, raw_version))

    payload = {
        'backend': 'legacy',
        'capability_id': capability,
        'target': result.target,
        'options': {'timeout_minutes': 1},
        'tool': result.tool,
        'tool_version': raw_version,
        'exit_code': result.exit_code,
        'stdout': result.stdout,
        'stderr': result.stderr,
        'artifact_hashes': {
            'adapter.amass-v5': _digest('/usr/local/bin/amass'),
            'binary.amass-v5': _digest('/usr/local/libexec/amass-real'),
            'patch.amass-v5-engine-auth': _digest(
                '/opt/aegis-runner/amass-v5.1.1-aegis-engine-auth.patch'
            ),
        },
        'runtime_provenance': {'provider': 'legacy-native-worker'},
    }
    (artifact_dir / 'legacy-execution.json').write_text(
        json.dumps(payload, sort_keys=True) + '\n', encoding='utf-8'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
