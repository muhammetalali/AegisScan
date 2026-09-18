#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from fastapi_app.services.kali_semgrep_provider import KaliSemgrepProviderError
from fastapi_app.services.semgrep_execution_provider import (
    legacy_semgrep_disabled,
    run_semgrep_with_provider,
)
from fastapi_app.tasks.advanced_scans import _semgrep_findings


SOURCE = '/workspace/source'
ARTIFACTS = Path('/artifacts')


def _assert_local_runtime_absent() -> None:
    assert shutil.which('semgrep') is None, shutil.which('semgrep')
    assert shutil.which('pysemgrep') is None, shutil.which('pysemgrep')
    assert importlib.util.find_spec('semgrep') is None


def _run(ref: str, key: str):
    return run_semgrep_with_provider(
        source=SOURCE,
        timeout_seconds=120,
        routing_key=key,
        execution_ref=ref,
        authorization_ref='auth-m6',
        scope_ref='project:m6:asset:code',
        state_getter=lambda: 'running',
    )


def default_kali() -> None:
    _assert_local_runtime_absent()
    assert legacy_semgrep_disabled() is True
    result = _run('semgrep-m6-default', 'semgrep-m6-default')
    assert result.routing['mode'] == 'default-kali', result.routing
    assert result.routing['selected_provider'] == 'kali', result.routing
    assert result.routing['reason'] == 'default-kali-parity-approved', result.routing
    assert result.runtime['provider'] == 'aegis-kali-code', result.runtime
    assert result.runtime['linux_privilege']['allowed_capabilities'] == [], result.runtime
    assert result.exit_code in {0, 1}, (result.exit_code, result.stderr)

    payload = json.loads(result.stdout)
    assert len(payload.get('results', [])) == 1, payload
    findings = _semgrep_findings(result.stdout)
    assert len(findings) == 1, findings
    assert findings[0]['path'] == '/workspace/source/app.py', findings
    assert findings[0]['check_id'].endswith('aegis.semgrep.parity.eval'), findings

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / 'retired-default-kali.json').write_text(result.stdout, encoding='utf-8')
    (ARTIFACTS / 'retired-default-kali-result.json').write_text(
        json.dumps(
            {'routing': result.routing, 'runtime': result.runtime, 'finding': findings[0]},
            sort_keys=True,
            indent=2,
        ),
        encoding='utf-8',
    )


def retired_routes() -> None:
    _assert_local_runtime_absent()
    results: list[dict[str, str]] = []
    for mode in ('legacy', 'canary'):
        os.environ['AEGIS_SEMGREP_PROVIDER'] = mode
        os.environ['AEGIS_KALI_SEMGREP_CANARY_BPS'] = '0'
        try:
            _run(f'semgrep-m6-{mode}', f'semgrep-m6-{mode}')
        except KaliSemgrepProviderError as exc:
            assert 'previous release' in str(exc), exc
            results.append({'mode': mode, 'result': 'rejected', 'error': str(exc)})
        else:
            raise AssertionError(f'retired Semgrep route unexpectedly executed: {mode}')

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / 'retired-routes.json').write_text(
        json.dumps(results, sort_keys=True, indent=2),
        encoding='utf-8',
    )


def outage() -> None:
    _assert_local_runtime_absent()
    os.environ['AEGIS_SEMGREP_PROVIDER'] = 'default-kali'
    os.environ['AEGIS_KALI_SEMGREP_CANARY_BPS'] = '0'
    try:
        _run('semgrep-m6-outage', 'semgrep-m6-outage')
    except KaliSemgrepProviderError as exc:
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS / 'retired-provider-outage.json').write_text(
            json.dumps({'fail_closed': True, 'error': str(exc)}, sort_keys=True, indent=2),
            encoding='utf-8',
        )
        return
    raise AssertionError('retired Semgrep provider outage silently fell back')


def main() -> int:
    actions = {
        'default': default_kali,
        'retired-routes': retired_routes,
        'outage': outage,
    }
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action not in actions:
        raise SystemExit(f"usage: {sys.argv[0]} <{'|'.join(actions)}>")
    actions[action]()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
