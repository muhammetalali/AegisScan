#!/usr/bin/env python3
"""Prove programmatic automation and installed CLI converge on one governed execution."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from aegis.platform_client import PlatformClient


STATE_PATH = Path(os.getenv(
    'AEGIS_GOVERNED_STATE_PATH',
    'aegis-platform/ci-artifacts/governed-execution-state.json',
))
ARTIFACT_DIR = STATE_PATH.parent


def require_state() -> dict:
    if not STATE_PATH.is_file():
        raise RuntimeError(f'Governed execution state not found: {STATE_PATH}')
    payload = json.loads(STATE_PATH.read_text(encoding='utf-8'))
    required = {'project_id', 'asset_id', 'capability_id', 'depth', 'idempotency_key', 'scan_id', 'execution_contract'}
    missing = sorted(required - set(payload))
    if missing:
        raise RuntimeError(f'Governed execution state is missing fields: {missing}')
    return payload


def assert_reuse(label: str, result: dict, initial: dict) -> None:
    if result.get('idempotency_reused') is not True:
        raise RuntimeError(f'{label} did not reuse the canonical idempotent execution: {result!r}')
    scan = result.get('scan') if isinstance(result.get('scan'), dict) else {}
    if scan.get('id') != initial['scan_id']:
        raise RuntimeError(f'{label} returned a different Scan identity: {result!r}')
    contract = result.get('execution_contract')
    if contract != initial['execution_contract']:
        raise RuntimeError(f'{label} returned execution contract drift')
    if contract.get('contract_version') != '1.0' or contract.get('policy_version') != 'capability-execution.v4':
        raise RuntimeError(f'{label} returned an unsupported governed execution contract: {contract!r}')


def main() -> int:
    base_url = os.environ['AEGIS_PLATFORM_URL']
    email = os.environ['AEGIS_EMAIL']
    password = os.environ['AEGIS_PASSWORD']
    initial = require_state()

    client = PlatformClient(base_url)
    client.login(email, password)
    automation = client.execute_capability(
        project_id=initial['project_id'],
        asset_id=initial['asset_id'],
        capability_id=initial['capability_id'],
        depth=initial['depth'],
        options={},
        credential_refs=[],
        idempotency_key=initial['idempotency_key'],
        correlation_id=f"automation-corr-{os.getenv('GITHUB_RUN_ID', 'local')}-{os.getenv('GITHUB_RUN_ATTEMPT', '1')}",
    )
    assert_reuse('automation', automation, initial)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACT_DIR / 'automation-governed-execution.json').write_text(
        json.dumps(automation, sort_keys=True, indent=2),
        encoding='utf-8',
    )

    command = [
        'aegis', 'run',
        '--project-id', initial['project_id'],
        '--asset-id', initial['asset_id'],
        '--capability', initial['capability_id'],
        '--depth', initial['depth'],
        '--idempotency-key', initial['idempotency_key'],
        '--correlation-id', f"cli-corr-{os.getenv('GITHUB_RUN_ID', 'local')}-{os.getenv('GITHUB_RUN_ATTEMPT', '1')}",
        '--json',
    ]
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    cli = json.loads(completed.stdout)
    assert_reuse('cli', cli, initial)
    (ARTIFACT_DIR / 'cli-governed-execution.json').write_text(
        json.dumps(cli, sort_keys=True, indent=2),
        encoding='utf-8',
    )

    if automation['execution_contract']['policy_fingerprint'] != initial['execution_contract']['policy_fingerprint']:
        raise RuntimeError('Automation policy result drifted from REST execution')
    if cli['execution_contract']['policy_fingerprint'] != initial['execution_contract']['policy_fingerprint']:
        raise RuntimeError('CLI policy result drifted from REST execution')

    print('MULTI_INTERFACE_GOVERNED_EXECUTION=PASS')
    print(f"scan_id={initial['scan_id']}")
    print(f"policy_fingerprint={initial['execution_contract']['policy_fingerprint']}")
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'MULTI_INTERFACE_GOVERNED_EXECUTION=FAIL: {exc}', file=sys.stderr, flush=True)
        raise
