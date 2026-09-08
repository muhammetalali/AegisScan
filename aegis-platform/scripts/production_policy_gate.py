from __future__ import annotations

from types import SimpleNamespace

from fastapi_app.services import scanner_adapters


def _completed():
    return SimpleNamespace(returncode=0, stdout='', stderr='')


def test_nuclei_enforces_dns_egress_and_disables_redirects(monkeypatch, tmp_path):
    calls = []
    command = []

    def authorized(target, **kwargs):
        calls.append((target, kwargs))
        return ()

    def run(args, **kwargs):
        command.extend(args)
        return _completed()

    monkeypatch.setattr(scanner_adapters, 'require_authorized_target', authorized)
    monkeypatch.setattr(scanner_adapters.shutil, 'which', lambda name: f'/usr/local/bin/{name}')
    monkeypatch.setattr(scanner_adapters.subprocess, 'run', run)
    monkeypatch.setenv('NUCLEI_TEMPLATES_DIR', str(tmp_path))

    result = scanner_adapters.run_nuclei('https://approved.example', timeout=15)

    assert result.tool == 'nuclei'
    assert calls == [
        ('https://approved.example', {'url': True, 'resolve_dns': True}),
    ]
    assert '-dr' in command
    assert command[command.index('-u') + 1] == 'https://approved.example'


def test_network_scanners_enforce_worker_dns_egress(monkeypatch):
    calls = []

    def authorized(target, **kwargs):
        calls.append((target, kwargs))
        return ()

    monkeypatch.setattr(scanner_adapters, 'require_authorized_target', authorized)
    monkeypatch.setattr(scanner_adapters.shutil, 'which', lambda name: f'/usr/bin/{name}')
    monkeypatch.setattr(scanner_adapters.subprocess, 'run', lambda *_args, **_kwargs: _completed())

    scanner_adapters.run_nmap('approved.example', timeout=15)
    scanner_adapters.run_masscan('10.20.0.0/16', ports='80', rate=10, timeout=15)

    assert calls == [
        ('approved.example', {'resolve_dns': True}),
        ('10.20.0.0/16', {'resolve_dns': True}),
    ]
