from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from fastapi_app.services.kali_masscan_provider import KaliMasscanProviderError
from fastapi_app.services.masscan_execution_provider import (
    legacy_masscan_disabled,
    run_masscan_with_provider,
)
from fastapi_app.services.masscan_semantic_parity import masscan_semantic_snapshot


ARTIFACTS = Path('/artifacts')
TARGET = '172.31.6.10'
COMMON = {
    'target': TARGET,
    'ports': '22,80',
    'rate': 1000,
    'timeout_seconds': 120,
    'authorization_ref': 'auth-m6',
    'scope_ref': 'project:m6:asset:masscan',
    'state_getter': lambda: 'running',
}


def _write(name: str, payload: object) -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / name).write_text(
        json.dumps(payload, sort_keys=True, indent=2) + '\n',
        encoding='utf-8',
    )


def _assert_local_runtime_absent() -> None:
    assert shutil.which('masscan') is None, shutil.which('masscan')
    assert not Path('/usr/bin/masscan').exists()


def _run(ref: str, key: str):
    return run_masscan_with_provider(
        routing_key=key,
        execution_ref=ref,
        **COMMON,
    )


def default_kali() -> None:
    _assert_local_runtime_absent()
    assert legacy_masscan_disabled() is True
    result = _run('masscan-m6-default', 'masscan-m6-default')
    assert result.routing['mode'] == 'default-kali', result.routing
    assert result.routing['selected_provider'] == 'kali', result.routing
    assert result.routing['reason'] == 'default-kali-parity-approved', result.routing
    assert result.runtime['provider'] == 'aegis-kali-network-masscan', result.runtime
    assert result.runtime['linux_privilege']['allowed_capabilities'] == ['CAP_NET_RAW'], result.runtime
    assert result.exit_code == 0, result.stderr
    snapshot = masscan_semantic_snapshot(result.stdout)
    expected = [
        {'ip': TARGET, 'protocol': 'tcp', 'port': 22},
        {'ip': TARGET, 'protocol': 'tcp', 'port': 80},
    ]
    assert snapshot['observations'] == expected, snapshot
    (ARTIFACTS / 'retired-default-kali.json').write_text(result.stdout, encoding='utf-8')
    _write('retired-default-kali-result.json', {
        'routing': result.routing,
        'runtime': result.runtime,
        'semantic_snapshot': snapshot,
    })


def retired_routes() -> None:
    _assert_local_runtime_absent()
    results: list[dict[str, str]] = []
    for mode, bps in (('legacy', '0'), ('canary', '0'), ('canary', '2500')):
        os.environ['AEGIS_MASSCAN_PROVIDER'] = mode
        os.environ['AEGIS_KALI_MASSCAN_CANARY_BPS'] = bps
        try:
            _run(f'masscan-m6-{mode}-{bps}', f'masscan-m6-{mode}-{bps}')
        except KaliMasscanProviderError as exc:
            assert 'previous release' in str(exc), exc
            results.append({'mode': mode, 'bps': bps, 'result': 'rejected', 'error': str(exc)})
        else:
            raise AssertionError(f'retired Masscan route unexpectedly executed: {mode}/{bps}')
    _write('retired-routes.json', results)


def outage() -> None:
    _assert_local_runtime_absent()
    os.environ['AEGIS_MASSCAN_PROVIDER'] = 'default-kali'
    os.environ['AEGIS_KALI_MASSCAN_CANARY_BPS'] = '0'
    try:
        _run('masscan-m6-outage', 'masscan-m6-outage')
    except KaliMasscanProviderError as exc:
        _write('retired-provider-outage.json', {'fail_closed': True, 'error': str(exc)})
        return
    raise AssertionError('retired Masscan provider outage silently fell back')


ACTIONS = {
    'default': default_kali,
    'retired-routes': retired_routes,
    'outage': outage,
}


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action not in ACTIONS:
        raise SystemExit(f"usage: {sys.argv[0]} <{'|'.join(ACTIONS)}>")
    ACTIONS[action]()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
