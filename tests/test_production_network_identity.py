import importlib.util
import ipaddress
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "aegis-platform/scripts/production_network_identity.py"
SPEC = importlib.util.spec_from_file_location("production_network_identity", SOURCE)
assert SPEC and SPEC.loader
network = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(network)


def route(ip="10.42.7.1", interface="enp7s0", metric=100):
    return [{"dst": "default", "gateway": ip, "dev": interface, "metric": metric}]


def addr(ip="10.42.7.25", prefix=24, interface="enp7s0", *, dynamic=True):
    return [
        {
            "ifname": interface,
            "operstate": "UP",
            "addr_info": [
                {
                    "family": "inet", "local": ip, "prefixlen": prefix,
                    "scope": "global", "dynamic": dynamic,
                }
            ],
        }
    ]


def test_auto_dhcp_detects_actual_route_not_a_static_ens33_address():
    result = network.discover(route(), addr())
    assert result == {
        "interface": "enp7s0",
        "ipv4": "10.42.7.25",
        "cidr": "10.42.7.0/24",
        "gateway": "10.42.7.1",
        "address_family": "ipv4",
        "allocation": "dhcp",
    }


def test_auto_dhcp_covers_multiple_company_private_subnets():
    scenarios = [
        ("10.8.0.1", "10.8.12.5", 16, "10.8.0.0/16"),
        ("172.20.5.1", "172.20.5.18", 24, "172.20.5.0/24"),
        ("192.168.200.254", "192.168.200.3", 24, "192.168.200.0/24"),
        ("100.64.1.1", "100.64.1.10", 24, "100.64.1.0/24"),
    ]
    for gateway, ip, mask, subnet in scenarios:
        assert network.discover(route(gateway), addr(ip, mask))["cidr"] == subnet


def test_discovers_preferred_default_route_without_docker_or_other_uplinks():
    routes = route("192.168.50.1", "enp6s0", 50)
    routes.extend(route("10.0.0.1", "enp7s0", 200))
    assert network.discover(routes, addr("192.168.50.22", 24, "enp6s0"))["interface"] == "enp6s0"


def test_equal_default_route_metrics_do_not_guess_which_company_network():
    routes = route("10.0.0.1", "enp6s0", 100) + route("172.16.0.1", "enp7s0", 100)
    with pytest.raises(network.NetworkDiscoveryError, match="equally"):
        network.discover(routes, addr())


def test_rejects_static_lease_public_gateway_and_gateway_outside_subnet():
    with pytest.raises(network.NetworkDiscoveryError, match="dynamic"):
        network.discover(route(), addr(dynamic=False))
    with pytest.raises(network.NetworkDiscoveryError, match="approved private"):
        network.discover(route("8.8.8.8"), addr())
    with pytest.raises(network.NetworkDiscoveryError, match="outside"):
        network.discover(route("10.45.0.1"), addr())


def test_rejects_multiple_dynamic_ips_and_down_link():
    rows = addr()
    rows[0]["addr_info"].append({
        "family": "inet", "local": "10.42.7.26", "prefixlen": 24,
        "scope": "global", "dynamic": True,
    })
    with pytest.raises(network.NetworkDiscoveryError, match="exactly one"):
        network.discover(route(), rows)
    down = addr()
    down[0]["operstate"] = "DOWN"
    with pytest.raises(network.NetworkDiscoveryError, match="not up"):
        network.discover(route(), down)


def test_cli_identity_uses_detected_interface_without_mutating_network(monkeypatch, capsys):
    def fake_ip_json(*arguments):
        if arguments == ("route", "show", "default"):
            return route()
        if arguments == ("addr", "show", "dev", "enp7s0"):
            return addr()
        raise AssertionError(f"unexpected network operation: {arguments}")

    monkeypatch.setattr(network, "_ip_json", fake_ip_json)
    monkeypatch.setattr("sys.argv", ["identity", "--format", "tsv"])
    assert network.main() == 0
    assert capsys.readouterr().out.strip() == "enp7s0\t10.42.7.0/24\t10.42.7.25\t10.42.7.1"


def test_cli_fails_closed_if_no_route(monkeypatch, capsys):
    monkeypatch.setattr(network, "_ip_json", lambda *args: [])
    monkeypatch.setattr("sys.argv", ["identity"])
    assert network.main() == 1
    assert "DISCOVERY_FAILED" in capsys.readouterr().err
