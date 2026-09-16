from fastapi_app.services.nmap_semantic_parity import compare_nmap_semantics, nmap_semantic_snapshot


def _xml(product='OpenSSH', version='9.2'):
    return f'''<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="{product}" version="{version}"/></port>
    </ports></host></nmaprun>'''


def test_snapshot_is_order_stable():
    snapshot = nmap_semantic_snapshot(_xml())
    assert [item['port'] for item in snapshot['hosts'][0]['ports']] == [22, 80]
    assert snapshot['open_ports'] == 2


def test_identical_semantics_are_equivalent():
    result = compare_nmap_semantics(_xml(), _xml())
    assert result['equivalent'] is True


def test_finding_relevant_service_drift_fails_parity():
    result = compare_nmap_semantics(_xml(), _xml(product='Dropbear', version='2025.88'))
    assert result['equivalent'] is False
