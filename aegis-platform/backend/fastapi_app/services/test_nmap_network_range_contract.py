from __future__ import annotations

import pytest

from fastapi_app.services.capability_planner import planning_summary
from fastapi_app.services.nmap_parser import parse_nmap_xml
from fastapi_app.services.capability_registry import get_capability, scan_type_for_asset
from fastapi_app.services.scope_authorization import (
    ScopeAuthorizationError,
    is_target_authorized,
    require_authorized_target,
)


@pytest.mark.parametrize('depth', ['quick', 'standard', 'deep', 'comprehensive'])
def test_new_authorized_network_range_is_planned_for_existing_nmap(depth):
    plan = planning_summary('network_range', depth)
    nmap = [entry for entry in plan['plan'] if entry['capability_id'] == 'network.nmap']
    assert len(nmap) == 1
    assert nmap[0]['tool'] == 'nmap'
    assert nmap[0]['execution_ready'] is True


@pytest.mark.parametrize(
    ('asset_type', 'expected'),
    [('ip_address', 'ip'), ('domain', 'ip'), ('network_range', 'network')],
)
def test_nmap_scan_type_matches_actual_asset(asset_type, expected):
    capability = get_capability('network.nmap')
    assert asset_type in capability.asset_types
    assert scan_type_for_asset(capability, asset_type) == expected


def test_other_engines_retain_their_existing_scan_type():
    masscan = get_capability('network.masscan')
    assert scan_type_for_asset(masscan, 'network_range') == 'network'


def test_incompatible_nmap_asset_stays_denied():
    with pytest.raises(ValueError, match='does not support'):
        scan_type_for_asset(get_capability('network.nmap'), 'website')


def test_adding_an_asset_does_not_silently_widen_global_authorized_scope(monkeypatch):
    monkeypatch.setenv('AEGIS_LAB_NETWORK_CIDRS', '192.168.49.0/24')
    monkeypatch.delenv('AUTHORIZED_SCAN_TARGETS', raising=False)
    assert is_target_authorized('192.168.49.0/24')
    assert not is_target_authorized('192.168.149.0/24')
    assert not is_target_authorized('172.23.192.0/20')
    assert not is_target_authorized('192.168.0.0/16')
    with pytest.raises(ScopeAuthorizationError):
        require_authorized_target('192.168.149.0/24')



def test_one_nmap_cidr_execution_preserves_both_hosts_and_ports():
    """Parser receipt must not collapse distinct hosts into the parent CIDR."""
    xml = """<nmaprun>
      <host><status state="up"/><address addr="192.168.49.128" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port></ports>
      </host>
      <host><status state="up"/><address addr="192.168.49.137" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
      </host>
    </nmaprun>"""
    parsed = parse_nmap_xml(xml)
    assert parsed['host_count'] == 2
    assert parsed['open_ports'] == 2
    assert {(host['ip'], port['port']) for host in parsed['hosts'] for port in host['ports']} == {
        ('192.168.49.128', 21), ('192.168.49.137', 22)
    }
