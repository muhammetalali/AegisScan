from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi_app.services import semgrep_execution_provider as execution
from fastapi_app.services.kali_semgrep_provider import (
    KaliSemgrepProviderError,
    semgrep_provider_decision,
)


def _kwargs(routing_key: str = 'scan-1') -> dict:
    return {
        'source': '/workspace/source',
        'timeout_seconds': 120,
        'routing_key': routing_key,
        'execution_ref': 'scan:scan-1:semgrep',
        'authorization_ref': 'authorization-1',
        'scope_ref': 'project:p1:asset:a1',
        'state_getter': lambda: 'running',
    }


def _legacy_result() -> SimpleNamespace:
    return SimpleNamespace(
        tool='semgrep',
        target='/workspace/source',
        exit_code=1,
        stdout=json.dumps({
            'results': [{
                'check_id': 'aegis.semgrep.parity.eval',
                'path': '/workspace/source/app.py',
                'start': {'line': 4},
                'extra': {'message': 'Aegis Semgrep parity fixture', 'severity': 'WARNING'},
            }],
            'errors': [],
        }),
        stderr='',
    )


def _selected_key() -> str:
    return next(
        f'semgrep-canary-{index}'
        for index in range(10000)
        if semgrep_provider_decision(routing_key=f'semgrep-canary-{index}').selected_provider == 'kali'
    )


def _fake_snapshot() -> SimpleNamespace:
    root = Path('/var/lib/aegis-semgrep') / ('a' * 64)
    return SimpleNamespace(
        snapshot_id='a' * 64,
        source_sha256='b' * 64,
        source_entry='.',
        root=root,
        original_root=Path('/workspace/source'),
        cleanup=lambda: None,
    )


def _kali_result(snapshot: SimpleNamespace) -> dict:
    return {
        'tool': 'semgrep',
        'exit_code': 1,
        'stdout': json.dumps({
            'results': [{
                'check_id': 'aegis.semgrep.parity.eval',
                'path': str(snapshot.root / 'app.py'),
                'start': {'line': 4},
                'extra': {'message': 'Aegis Semgrep parity fixture', 'severity': 'WARNING'},
            }],
            'errors': [],
        }),
        'stderr': '',
        'runtime': {'provider': 'aegis-kali-code'},
    }


def test_library_fallback_remains_legacy_without_deployment_policy(monkeypatch):
    monkeypatch.delenv('AEGIS_SEMGREP_PROVIDER', raising=False)
    monkeypatch.delenv('AEGIS_KALI_SEMGREP_CANARY_BPS', raising=False)
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    monkeypatch.setattr(execution, 'run_semgrep', lambda *args, **kwargs: _legacy_result())
    monkeypatch.setattr(
        execution,
        'execute_kali_semgrep',
        lambda **kwargs: pytest.fail('Kali must not run without deployment policy'),
    )

    result = execution.run_semgrep_with_provider(**_kwargs())

    assert result.routing['mode'] == 'legacy'
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'
    assert result.runtime['provider'] == 'legacy-native-worker'


def test_default_kali_routes_without_canary_assignment(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'default-kali')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '0')
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    snapshot = _fake_snapshot()
    monkeypatch.setattr(execution, '_stage_source', lambda source: snapshot)
    monkeypatch.setattr(
        execution,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('legacy must not run under default-kali'),
    )
    monkeypatch.setattr(execution, 'execute_kali_semgrep', lambda **kwargs: _kali_result(snapshot))

    first = execution.run_semgrep_with_provider(**_kwargs('scan-default-a'))
    second = execution.run_semgrep_with_provider(**_kwargs('scan-default-b'))

    for result in (first, second):
        assert result.routing['mode'] == 'default-kali'
        assert result.routing['selected_provider'] == 'kali'
        assert result.routing['parity_approved'] is True
        assert result.routing['canary_bps'] == 0
        assert result.routing['bucket'] is None
        assert result.routing['routing_key_digest'] == ''
        assert result.routing['reason'] == 'default-kali-parity-approved'
        assert result.runtime['provider'] == 'aegis-kali-code'
        assert json.loads(result.stdout)['results'][0]['path'] == '/workspace/source/app.py'


def test_default_kali_failure_never_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'default-kali')
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    monkeypatch.setattr(execution, '_stage_source', lambda source: _fake_snapshot())
    monkeypatch.setattr(
        execution,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('legacy fallback is forbidden'),
    )

    def _failed(**kwargs):
        raise KaliSemgrepProviderError('provider unavailable')

    monkeypatch.setattr(execution, 'execute_kali_semgrep', _failed)
    with pytest.raises(KaliSemgrepProviderError, match='provider unavailable'):
        execution.run_semgrep_with_provider(**_kwargs())


def test_explicit_legacy_mode_remains_m5_administrative_rollback(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'legacy')
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    monkeypatch.setattr(execution, 'run_semgrep', lambda *args, **kwargs: _legacy_result())
    monkeypatch.setattr(
        execution,
        'execute_kali_semgrep',
        lambda **kwargs: pytest.fail('Kali must not run during explicit rollback'),
    )

    result = execution.run_semgrep_with_provider(**_kwargs())

    assert result.routing['mode'] == 'legacy'
    assert result.routing['selected_provider'] == 'legacy'
    assert result.routing['reason'] == 'legacy-default'


def test_canary_assignment_is_stable_and_has_selected_and_holdback(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '2500')
    selected = holdback = None
    for index in range(10000):
        key = f'semgrep-canary-{index}'
        decision = semgrep_provider_decision(routing_key=key)
        assert semgrep_provider_decision(routing_key=key) == decision
        if decision.selected_provider == 'kali' and selected is None:
            selected = decision
        if decision.selected_provider == 'legacy' and holdback is None:
            holdback = decision
        if selected and holdback:
            break
    assert selected is not None and selected.reason == 'canary-selected'
    assert holdback is not None and holdback.reason == 'canary-holdback'
    assert selected.canary_bps == holdback.canary_bps == 2500


def test_canary_zero_is_explicit_rollback(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '0')
    decision = semgrep_provider_decision(routing_key='scan-1')
    assert decision.selected_provider == 'legacy'
    assert decision.reason == 'canary-rollback-zero'
    assert decision.bucket is None


def test_canary_rejects_rollout_above_twenty_five_percent(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '2501')
    with pytest.raises(KaliSemgrepProviderError, match='0 to 2500'):
        semgrep_provider_decision(routing_key='scan-1')


def test_legacy_holdback_preserves_existing_adapter(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'legacy')
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    monkeypatch.setattr(execution, 'run_semgrep', lambda *args, **kwargs: _legacy_result())
    monkeypatch.setattr(
        execution,
        'execute_kali_semgrep',
        lambda **kwargs: pytest.fail('Kali must not execute in legacy holdback'),
    )

    result = execution.run_semgrep_with_provider(**_kwargs())

    assert result.routing['selected_provider'] == 'legacy'
    assert result.runtime['provider'] == 'legacy-native-worker'
    assert result.stdout == _legacy_result().stdout


def test_selected_kali_failure_never_falls_back_to_legacy(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '2500')
    selected = _selected_key()
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    monkeypatch.setattr(
        execution,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('silent legacy fallback is forbidden'),
    )
    snapshot = SimpleNamespace(
        snapshot_id='a' * 64,
        source_sha256='b' * 64,
        source_entry='.',
        root=Path('/var/lib/aegis-semgrep') / ('a' * 64),
        original_root=Path('/workspace/source'),
        cleanup=lambda: None,
    )
    monkeypatch.setattr(execution, '_stage_source', lambda source: snapshot)

    def _failed(**kwargs):
        raise KaliSemgrepProviderError('provider unavailable')

    monkeypatch.setattr(execution, 'execute_kali_semgrep', _failed)
    with pytest.raises(KaliSemgrepProviderError, match='provider unavailable'):
        execution.run_semgrep_with_provider(**_kwargs(selected))


def test_selected_kali_rewrites_snapshot_paths_to_original_source(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_SEMGREP_CANARY_BPS', '2500')
    selected = _selected_key()
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    snapshot_root = Path('/var/lib/aegis-semgrep') / ('a' * 64)
    snapshot = SimpleNamespace(
        snapshot_id='a' * 64,
        source_sha256='b' * 64,
        source_entry='.',
        root=snapshot_root,
        original_root=Path('/workspace/source'),
        cleanup=lambda: None,
    )
    monkeypatch.setattr(execution, '_stage_source', lambda source: snapshot)
    monkeypatch.setattr(
        execution,
        'run_semgrep',
        lambda *args, **kwargs: pytest.fail('legacy must not execute for selected cohort'),
    )
    candidate = json.dumps({
        'results': [{
            'check_id': 'aegis.semgrep.parity.eval',
            'path': str(snapshot_root / 'app.py'),
            'start': {'line': 4},
            'extra': {'message': 'Aegis Semgrep parity fixture', 'severity': 'WARNING'},
        }],
        'errors': [],
    })
    monkeypatch.setattr(execution, 'execute_kali_semgrep', lambda **kwargs: {
        'tool': 'semgrep',
        'exit_code': 1,
        'stdout': candidate,
        'stderr': '',
        'runtime': {'provider': 'aegis-kali-code'},
    })

    result = execution.run_semgrep_with_provider(**_kwargs(selected))
    payload = json.loads(result.stdout)

    assert result.routing['selected_provider'] == 'kali'
    assert payload['results'][0]['path'] == '/workspace/source/app.py'
    assert result.runtime['provider'] == 'aegis-kali-code'


def test_raw_kali_mode_is_not_admitted_by_production_execution_layer(monkeypatch):
    monkeypatch.setenv('AEGIS_SEMGREP_PROVIDER', 'kali')
    monkeypatch.setattr(execution, 'validate_code_target', lambda source: source)
    with pytest.raises(RuntimeError, match='not admitted by the governed production execution layer'):
        execution.run_semgrep_with_provider(**_kwargs())


def test_snapshot_rejects_symlinks_and_cleans_up(monkeypatch, tmp_path):
    workspace = tmp_path / 'workspace'
    source = tmp_path / 'source'
    source.mkdir()
    outside = tmp_path / 'outside.py'
    outside.write_text('pass\n', encoding='utf-8')
    (source / 'linked.py').symlink_to(outside)
    monkeypatch.setenv('AEGIS_SEMGREP_WORKSPACE_ROOT', str(workspace))
    monkeypatch.setattr(execution, 'validate_code_target', lambda source_value: str(source))

    with pytest.raises(KaliSemgrepProviderError, match='cannot contain symlinks'):
        execution._stage_source(str(source))
    assert list(workspace.iterdir()) == []
