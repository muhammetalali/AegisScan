from __future__ import annotations

from types import SimpleNamespace

from fastapi_app.services import kali_recon_provider as provider
from fastapi_app.services.native_tool_runtime import get_native_tool_spec
from fastapi_app.services.scanner_adapters import ScanResult
from fastapi_app.tasks import native_capabilities as native_task


def _key_for(selected_provider: str) -> str:
    for index in range(10_000):
        key = f'm4-task-{index}'
        decision = provider.recon_provider_decision('recon.fierce', routing_key=key)
        if decision.selected_provider == selected_provider:
            return key
    raise AssertionError(f'unable to derive {selected_provider} routing key')


def _scan(scan_id: str):
    return SimpleNamespace(id=scan_id, project_id='project-m4', asset_id='asset-m4')


def _authorization():
    return SimpleNamespace(id='authorization-m4')


def test_native_execution_uses_legacy_for_canary_holdback_and_persists_decision(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '2500')
    scan_id = _key_for('legacy')
    calls = []

    def legacy(*args, **kwargs):
        calls.append(('legacy', args, kwargs))
        return ScanResult(tool='fierce', target='parity.test', exit_code=0, stdout='legacy', stderr='')

    def kali(**kwargs):
        raise AssertionError('holdback execution must not reach Kali provider')

    monkeypatch.setattr(native_task, 'run_native_tool', legacy)
    monkeypatch.setattr(native_task, 'execute_kali_recon', kali)

    result, provenance = native_task._execute_runtime(
        capability_id='recon.fierce',
        target='parity.test',
        options={},
        scan=_scan(scan_id),
        authorization=_authorization(),
        spec=get_native_tool_spec('recon.fierce'),
        credential_materials=(),
    )

    assert result.stdout == 'legacy'
    assert len(calls) == 1
    decision = provenance['routing_decision']
    assert provenance['provider'] == 'legacy-native-worker'
    assert decision['selected_provider'] == 'legacy'
    assert decision['reason'] == 'canary-holdback'
    assert decision['routing_key_digest'] == provider.recon_provider_decision(
        'recon.fierce', routing_key=scan_id
    ).routing_key_digest


def test_native_execution_uses_kali_for_selected_canary_and_persists_decision(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '2500')
    scan_id = _key_for('kali')
    captured = {}

    def legacy(*args, **kwargs):
        raise AssertionError('selected canary execution must not use legacy runtime')

    def kali(**kwargs):
        captured.update(kwargs)
        return {
            'tool': 'fierce',
            'target': 'parity.test',
            'exit_code': 0,
            'stdout': 'kali',
            'stderr': '',
            'runtime': {
                'provider': 'aegis-kali-recon',
                'profile': 'recon',
                'provenance_authority': 'control-plane-deployment-pins',
            },
        }

    monkeypatch.setattr(native_task, 'run_native_tool', legacy)
    monkeypatch.setattr(native_task, 'execute_kali_recon', kali)

    result, provenance = native_task._execute_runtime(
        capability_id='recon.fierce',
        target='parity.test',
        options={},
        scan=_scan(scan_id),
        authorization=_authorization(),
        spec=get_native_tool_spec('recon.fierce'),
        credential_materials=(),
    )

    assert result.stdout == 'kali'
    assert captured['execution_ref'] == scan_id
    assert captured['authorization_ref'] == 'authorization-m4'
    assert captured['scope_ref'] == 'project:project-m4:asset:asset-m4'
    decision = provenance['routing_decision']
    assert provenance['provider'] == 'aegis-kali-recon'
    assert decision['selected_provider'] == 'kali'
    assert decision['reason'] == 'canary-selected'
    assert decision['routing_key_digest'] == provider.recon_provider_decision(
        'recon.fierce', routing_key=scan_id
    ).routing_key_digest


def test_zero_bps_routes_task_to_legacy_without_requiring_assignment_key(monkeypatch):
    monkeypatch.setenv('AEGIS_RECON_PROVIDER', 'canary')
    monkeypatch.setenv('AEGIS_KALI_RECON_CANARY_BPS', '0')
    monkeypatch.setattr(
        native_task,
        'run_native_tool',
        lambda *args, **kwargs: ScanResult(
            tool='fierce',
            target='parity.test',
            exit_code=0,
            stdout='rollback',
            stderr='',
        ),
    )
    monkeypatch.setattr(
        native_task,
        'execute_kali_recon',
        lambda **kwargs: (_ for _ in ()).throw(AssertionError('zero-bps rollback reached Kali')),
    )

    _, provenance = native_task._execute_runtime(
        capability_id='recon.fierce',
        target='parity.test',
        options={},
        scan=_scan('rollback-scan'),
        authorization=_authorization(),
        spec=get_native_tool_spec('recon.fierce'),
        credential_materials=(),
    )

    assert provenance['provider'] == 'legacy-native-worker'
    assert provenance['routing_decision']['reason'] == 'canary-rollback-zero'
