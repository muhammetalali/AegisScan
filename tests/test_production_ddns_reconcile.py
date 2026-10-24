import importlib.util
import ipaddress
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "aegis-platform/scripts"))


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


def _identity(interface="enp7s0", ip="10.21.7.134", cidr="10.21.7.0/24"):
    return {"interface": interface, "ipv4": ip, "cidr": cidr, "gateway": "10.21.7.1"}


def test_discover_dynamic_ipv4_accepts_dhcp_in_any_network_without_pinned_interface(monkeypatch):
    monkeypatch.setattr(ddns, "INTERFACE", None)
    monkeypatch.setattr(ddns, "APPROVED_NETWORK", None)
    selected = []
    monkeypatch.setattr(ddns, "current_identity", lambda nic: selected.append(nic) or _identity())
    assert ddns.discover_dynamic_ipv4() == ipaddress.ip_address("10.21.7.134")
    assert selected == [None]


@pytest.mark.parametrize("ip,cidr", [
    ("10.11.5.49", "10.11.5.0/24"),
    ("172.20.18.14", "172.20.16.0/22"),
    ("192.168.200.44", "192.168.200.0/24"),
])
def test_dhcp_network_changes_do_not_require_code_or_fixed_ip(monkeypatch, ip, cidr):
    monkeypatch.setattr(ddns, "INTERFACE", None)
    monkeypatch.setattr(ddns, "APPROVED_NETWORK", None)
    monkeypatch.setattr(ddns, "current_identity", lambda nic: _identity(ip=ip, cidr=cidr))
    assert ddns.discover_dynamic_ipv4() == ipaddress.ip_address(ip)


def test_explicit_legacy_interface_is_only_a_selector(monkeypatch):
    monkeypatch.setattr(ddns, "INTERFACE", "enp7s0")
    monkeypatch.setattr(ddns, "APPROVED_NETWORK", None)
    selected = []
    monkeypatch.setattr(ddns, "current_identity", lambda nic: selected.append(nic) or _identity())
    assert ddns.discover_dynamic_ipv4() == ipaddress.ip_address("10.21.7.134")
    assert selected == ["enp7s0"]


def test_legacy_boundary_is_constraint_not_a_fixed_address(monkeypatch):
    monkeypatch.setattr(ddns, "APPROVED_NETWORK", "10.21.0.0/16")
    monkeypatch.setattr(ddns, "current_identity", lambda nic: _identity())
    assert ddns.discover_dynamic_ipv4() == ipaddress.ip_address("10.21.7.134")
    monkeypatch.setattr(ddns, "APPROVED_NETWORK", "172.18.0.0/16")
    with pytest.raises(ddns.ReconcileError, match="outside approved ingress"):
        ddns.discover_dynamic_ipv4()


def test_ambiguous_network_fails_closed_without_guessing(monkeypatch):
    from production_network_identity import NetworkDiscoveryError
    monkeypatch.setattr(ddns, "INTERFACE", None)
    def ambiguous(nic):
        raise NetworkDiscoveryError("multiple equally preferred IPv4 default routes")
    monkeypatch.setattr(ddns, "current_identity", ambiguous)
    with pytest.raises(ddns.ReconcileError, match="cannot be proved"):
        ddns.discover_dynamic_ipv4()


def test_reconcile_noop_when_authoritative_record_matches(monkeypatch):
    expected = ipaddress.ip_address("192.168.49.134")
    monkeypatch.setattr(ddns, "discover_bound_dhcp_identity", lambda: ("enp7s0", expected, "192.168.49.0/24"))
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
    monkeypatch.setattr(ddns, "discover_bound_dhcp_identity", lambda: ("enp7s0", expected, "192.168.49.0/24"))
    monkeypatch.setattr(ddns, "authoritative_addresses", lambda: next(states))
    monkeypatch.setattr(ddns, "signed_update", updates.append)
    result = ddns.reconcile()
    assert updates == [expected]
    assert result["action"] == "updated"


def test_reconcile_fails_closed_on_post_update_mismatch(monkeypatch):
    expected = ipaddress.ip_address("192.168.49.134")
    wrong = ipaddress.ip_address("192.168.49.200")
    states = iter([[], [wrong]])
    monkeypatch.setattr(ddns, "discover_bound_dhcp_identity", lambda: ("enp7s0", expected, "192.168.49.0/24"))
    monkeypatch.setattr(ddns, "authoritative_addresses", lambda: next(states))
    monkeypatch.setattr(ddns, "signed_update", lambda _: None)
    with pytest.raises(ddns.ReconcileError, match="verification failed"):
        ddns.reconcile()


def test_reconcile_tracks_new_dhcp_lease_and_updates_the_same_fqdn(monkeypatch):
    """An IP change is a signed DNS update, not a new hardcoded hostname."""
    old = ipaddress.ip_address('10.21.7.134')
    new = ipaddress.ip_address('10.21.7.199')
    monkeypatch.setattr(ddns, 'discover_bound_dhcp_identity',
                        lambda: ('enp7s0', new, '10.21.7.0/24'))
    states = iter([[old], [new]])
    signed = []
    monkeypatch.setattr(ddns, 'authoritative_addresses', lambda: next(states))
    monkeypatch.setattr(ddns, 'signed_update', signed.append)
    result = ddns.reconcile()
    assert result['status'] == 'success'
    assert result['action'] == 'updated'
    assert result['interface'] == 'enp7s0'
    assert result['network_observed'] == '10.21.7.0/24'
    assert result['previous'] == [str(old)]
    assert signed == [new]
    assert result['fqdn'] == ddns.FQDN.rstrip('.')


def test_untrusted_network_fails_before_signed_dns_update(monkeypatch):
    """Discovery of a foreign network is not authorization to publish it."""
    monkeypatch.setattr(ddns, 'APPROVED_NETWORK', '10.88.0.0/16')
    monkeypatch.setattr(ddns, 'current_identity',
                        lambda nic: _identity(ip='172.21.7.8', cidr='172.21.7.0/24'))
    monkeypatch.setattr(ddns, 'authoritative_addresses',
                        lambda: (_ for _ in ()).throw(AssertionError('DNS queried before trust gate')))
    with pytest.raises(ddns.ReconcileError, match='outside approved ingress'):
        ddns.reconcile()
