from types import SimpleNamespace

from fastapi_app.services.scanner_adapters import ScanResult
from fastapi_app.tasks import native_capabilities


class _LegacyDecision:
    selected_provider = 'legacy'

    def as_dict(self):
        return {
            'schema': 'aegis.recon-provider-routing.v1',
            'mode': 'legacy',
            'selected_provider': 'legacy',
        }


def test_legacy_native_execution_forwards_bound_authorization_snapshot(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        native_capabilities,
        'recon_provider_decision',
        lambda capability_id, routing_key: _LegacyDecision(),
    )

    def fake_run_native_tool(capability_id, target, options, **kwargs):
        captured.update(
            capability_id=capability_id,
            target=target,
            options=options,
            approved_target=kwargs.get('approved_target'),
            approved_addresses=kwargs.get('approved_addresses'),
        )
        return ScanResult(
            tool='nbtscan',
            target=target,
            exit_code=0,
            stdout='',
            stderr='',
        )

    monkeypatch.setattr(native_capabilities, 'run_native_tool', fake_run_native_tool)

    scan = SimpleNamespace(
        id='scan-1',
        project_id='project-1',
        asset_id='asset-1',
        asset=SimpleNamespace(configuration={'resolved_ips': ['10.10.20.30']}),
    )
    authorization = SimpleNamespace(id='auth-1', target_snapshot='10.10.20.30')

    result, runtime = native_capabilities._execute_runtime(
        capability_id='network.nbtscan-host',
        target='10.10.20.30',
        options={},
        scan=scan,
        authorization=authorization,
        spec=object(),
        credential_materials=(),
    )

    assert result.target == '10.10.20.30'
    assert runtime['provider'] == 'legacy-native-worker'
    assert captured == {
        'capability_id': 'network.nbtscan-host',
        'target': '10.10.20.30',
        'options': {},
        'approved_target': '10.10.20.30',
        'approved_addresses': ('10.10.20.30',),
    }
