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



def test_target_route_uses_bridged_interface_without_static_nic_or_gateway(monkeypatch):
    def ip_json(*parts):
        assert parts == ("route", "get", "192.168.2.48")
        return [{
            "dst": "192.168.2.48",
            "dev": "ens37",
            "prefsrc": "192.168.2.121",
            "uid": 1000,
        }]
    monkeypatch.setattr(network, "_ip_json", ip_json)
    result = network.selected_target_route("192.168.2.48")
    assert result["interface"] == "ens37"
    assert result["source_ipv4"] == "192.168.2.121"
    assert result["route_type"] == "on-link"
    assert result["gateway"] is None
    assert result["scan_authorization"] == "not-inferred-from-connectivity"
    assert result["reachable"] == "not-proven-by-route"


def test_target_route_detects_vmware_nat_route_without_claiming_lan_access(monkeypatch):
    monkeypatch.setattr(network, "_ip_json", lambda *parts: [{
        "dst": "192.168.2.48",
        "dev": "ens33",
        "gateway": "192.168.49.2",
        "prefsrc": "192.168.49.136",
    }])
    result = network.selected_target_route("192.168.2.48")
    assert result["interface"] == "ens33"
    assert result["gateway"] == "192.168.49.2"
    assert result["route_type"] == "via-gateway"
    assert result["reachable"] == "not-proven-by-route"


def test_target_route_does_not_mistake_docker_bridge_for_company_nic(monkeypatch):
    monkeypatch.setattr(network, "_ip_json", lambda *parts: [{
        "dst": "172.20.0.35",
        "dev": "br-82bcd330ec4b",
        "prefsrc": "172.20.0.1",
    }])
    with pytest.raises(network.NetworkDiscoveryError, match="container-only"):
        network.selected_target_route("172.20.0.35")


@pytest.mark.parametrize("target", ["127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "not-an-ip"])
def test_target_route_rejects_unroutable_or_invalid_targets(target):
    with pytest.raises(network.NetworkDiscoveryError):
        network.selected_target_route(target)


def test_target_route_reads_only_iproute2_without_triggering_scan(monkeypatch, capsys):
    monkeypatch.setattr(network, "_ip_json", lambda *parts: [{
        "dst": "10.42.7.25",
        "dev": "enp7s0",
        "prefsrc": "10.42.7.3",
    }])
    monkeypatch.setattr("sys.argv", ["network-identity", "--target-route", "10.42.7.25"])
    assert network.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["route_type"] == "on-link"
    assert output["scan_authorization"] == "not-inferred-from-connectivity"


def test_windows_host_detects_physical_wifi_without_vmnet_hardcoding():
    context = network.windows_host_identity([
        {"name": "VMware Network Adapter VMnet8", "description": "VMware Virtual Ethernet",
         "index": 21, "up": True, "ipv4": "192.168.49.1", "prefix": 24, "gateway": None},
        {"name": "Wi-Fi", "description": "Intel Wi-Fi 6", "index": 18, "up": True,
         "ipv4": "192.168.2.121", "prefix": 24, "gateway": "192.168.2.1"},
    ])
    assert context["platform"] == "windows"
    assert context["scan_authorization"] == "not-inferred-from-network-access"
    assert context["networks"] == [{
        "interface": "Wi-Fi", "interface_index": 18,
        "ipv4": "192.168.2.121", "subnet": "192.168.2.0/24",
        "gateway": "192.168.2.1", "origin": "windows-active-adapter",
    }]


def test_windows_host_lan_reacts_to_dhcp_and_adapter_changes():
    first = network.windows_host_identity([{
        "name": "Wi-Fi", "description": "Intel Wi-Fi", "index": 18, "up": True,
        "ipv4": "10.88.5.15", "prefix": 24, "gateway": "10.88.5.1",
    }])
    second = network.windows_host_identity([{
        "name": "Ethernet", "description": "Intel Ethernet", "index": 7, "up": True,
        "ipv4": "172.22.9.88", "prefix": 23, "gateway": "172.22.8.1",
    }])
    assert first["networks"][0]["subnet"] == "10.88.5.0/24"
    assert second["networks"][0]["subnet"] == "172.22.8.0/23"


def test_windows_host_does_not_claim_authorization_or_guess_missing_adapter():
    assert network.windows_host_identity([])["networks"] == []
    result = network.windows_host_identity([
        {"name": "VPN", "description": "Corporate VPN virtual adapter", "index": 18,
         "up": True, "ipv4": "10.9.1.3", "prefix": 24, "gateway": "10.9.1.1"},
        {"name": "Wireless", "description": "Intel Wi-Fi", "index": 24,
         "up": False, "ipv4": "192.168.4.6", "prefix": 24, "gateway": "192.168.4.1"},
    ])
    assert not result["networks"]
    assert result["scan_authorization"] == "not-inferred-from-network-access"


def test_windows_host_discovery_is_not_executed_on_ubuntu(monkeypatch):
    monkeypatch.setattr(network.sys, "platform", "linux")
    with pytest.raises(network.NetworkDiscoveryError, match="Windows host"):
        network.discover_windows_host()
