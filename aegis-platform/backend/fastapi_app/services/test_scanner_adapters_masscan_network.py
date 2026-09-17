from __future__ import annotations

from types import SimpleNamespace

import pytest

from fastapi_app.services import scanner_adapters


def _stub_execution(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    observed: list[str] = []
    monkeypatch.setattr(scanner_adapters, 'require_authorized_target', lambda *args, **kwargs: None)
    monkeypatch.setattr(scanner_adapters.shutil, 'which', lambda name: '/usr/bin/masscan' if name == 'masscan' else None)

    def fake_run(argv, **kwargs):
        observed.extend(argv)
        return SimpleNamespace(returncode=0, stdout='[]', stderr='')

    monkeypatch.setattr(scanner_adapters.subprocess, 'run', fake_run)
    return observed


def test_run_masscan_accepts_only_validated_explicit_link_metadata(monkeypatch: pytest.MonkeyPatch):
    argv = _stub_execution(monkeypatch)
    result = scanner_adapters.run_masscan(
        '172.31.1.10',
        ports='22,80',
        rate=1000,
        interface='eth0',
        adapter_ip='172.31.1.2',
        adapter_mac='02:42:ac:1f:01:02',
        router_mac='02:42:ac:1f:01:0a',
    )
    assert result.exit_code == 0
    assert argv == [
        '/usr/bin/masscan', '172.31.1.10', '-p', '22,80', '--rate', '1000',
        '--adapter', 'eth0',
        '--adapter-ip', '172.31.1.2',
        '--adapter-mac', '02:42:ac:1f:01:02',
        '--router-mac', '02:42:ac:1f:01:0a',
        '--output-format', 'json', '--output-filename', '-',
    ]


def test_run_masscan_default_command_is_unchanged(monkeypatch: pytest.MonkeyPatch):
    argv = _stub_execution(monkeypatch)
    scanner_adapters.run_masscan('172.31.1.10', ports='80', rate=500)
    assert '--adapter' not in argv
    assert '--adapter-ip' not in argv
    assert '--adapter-mac' not in argv
    assert '--router-mac' not in argv


@pytest.mark.parametrize(
    ('field', 'value'),
    [
        ('interface', 'eth0;id'),
        ('interface', 'x' * 16),
        ('adapter_ip', 'not-an-ip'),
        ('adapter_ip', '2001:db8::1'),
        ('adapter_mac', '00:11:22:33:44'),
        ('adapter_mac', '00:11:22:33:44:zz'),
        ('router_mac', '00-11-22-33-44'),
    ],
)
def test_run_masscan_rejects_invalid_link_metadata(monkeypatch: pytest.MonkeyPatch, field: str, value: str):
    _stub_execution(monkeypatch)
    kwargs = {field: value}
    with pytest.raises(ValueError, match='Masscan'):
        scanner_adapters.run_masscan('172.31.1.10', ports='80', rate=500, **kwargs)
