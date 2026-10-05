from types import SimpleNamespace

import pytest

from fastapi_app.services import scanner_adapters


def test_nmap_adapter_accepts_exact_bound_private_ip_without_static_allowlist(monkeypatch):
    monkeypatch.delenv('AUTHORIZED_SCAN_TARGETS', raising=False)
    monkeypatch.setattr(scanner_adapters.shutil, 'which', lambda binary: '/usr/bin/nmap')
    monkeypatch.setattr(
        scanner_adapters.subprocess,
        'run',
        lambda argv, **kwargs: SimpleNamespace(returncode=0, stdout='<nmaprun/>', stderr=''),
    )

    result = scanner_adapters.run_nmap(
        '10.10.20.30',
        approved_target='10.10.20.30',
    )

    assert result.target == '10.10.20.30'
    assert result.exit_code == 0
    assert result.stdout == '<nmaprun/>'


def test_nmap_adapter_rejects_private_ip_when_bound_snapshot_does_not_match(monkeypatch):
    monkeypatch.delenv('AUTHORIZED_SCAN_TARGETS', raising=False)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError('subprocess must not start for an unauthorized target')

    monkeypatch.setattr(scanner_adapters.subprocess, 'run', fail_if_called)

    with pytest.raises(ValueError, match='outside the server-side authorized scan scope'):
        scanner_adapters.run_nmap(
            '10.10.20.30',
            approved_target='10.10.20.31',
        )

    assert called is False
