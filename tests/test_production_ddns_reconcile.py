import importlib.util
import ipaddress
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def _load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ddns = _load(
    "production_ddns_reconcile",
    "aegis-platform/scripts/production_ddns_reconcile.py",
)


def _completed(stdout: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["ip"], returncode=0, stdout=stdout, stderr="")


def test_discover_dynamic_ipv4_accepts_one_dynamic_address(monkeypatch):
    output = (
        "2: ens33 inet 192.168.49.53/32 scope global ens33\n"
        "2: ens33 inet 192.168.49.134/24 scope global dynamic ens33\n"
    )
    monkeypatch.setattr(ddns, "run", lambda *args, **kwargs: _completed(output))
    assert ddns.discover_dynamic_ipv4() == ipaddress.ip_address("192.168.49.134")


def test_discover_dynamic_ipv4_rejects_multiple_addresses(monkeypatch):
    output = (
        "2: ens33 inet 192.168.49.134/24 scope global dynamic ens33\n"
        "2: ens33 inet 192.168.49.135/24 scope global dynamic ens33\n"
    )
    monkeypatch.setattr(ddns, "run", lambda *args, **kwargs: _completed(output))
    with pytest.raises(ddns.ReconcileError, match="exactly one"):
        ddns.discover_dynamic_ipv4()


def test_reconcile_noop_when_authoritative_record_matches(monkeypatch):
    expected = ipaddress.ip_address("192.168.49.134")
    monkeypatch.setattr(ddns, "discover_dynamic_ipv4", lambda: expected)
    monkeypatch.setattr(ddns, "authoritative_addresses", lambda: [expected])

    def unexpected_update(_):
        raise AssertionError("signed update must not run")

    monkeypatch.setattr(ddns, "signed_update", unexpected_update)
    result = ddns.reconcile()
    assert result["status"] == "success"
    assert result["action"] == "unchanged"


def test_reconcile_updates_then_verifies(monkeypatch):
    expected = ipaddress.ip_address("192.168.49.134")
    states = iter([[], [expected]])
    updates = []
    monkeypatch.setattr(ddns, "discover_dynamic_ipv4", lambda: expected)
    monkeypatch.setattr(ddns, "authoritative_addresses", lambda: next(states))
    monkeypatch.setattr(ddns, "signed_update", updates.append)
    result = ddns.reconcile()
    assert updates == [expected]
    assert result["action"] == "updated"


def test_reconcile_fails_closed_on_post_update_mismatch(monkeypatch):
    expected = ipaddress.ip_address("192.168.49.134")
    wrong = ipaddress.ip_address("192.168.49.200")
    states = iter([[], [wrong]])
    monkeypatch.setattr(ddns, "discover_dynamic_ipv4", lambda: expected)
    monkeypatch.setattr(ddns, "authoritative_addresses", lambda: next(states))
    monkeypatch.setattr(ddns, "signed_update", lambda _: None)
    with pytest.raises(ddns.ReconcileError, match="verification failed"):
        ddns.reconcile()
