from __future__ import annotations

from typing import Any

from .nmap_parser import parse_nmap_xml


def nmap_semantic_snapshot(raw_xml: str) -> dict[str, Any]:
    parsed = parse_nmap_xml(raw_xml)
    hosts: list[dict[str, Any]] = []
    for host in parsed.get('hosts', []):
        ports = []
        for port in host.get('ports', []):
            ports.append({
                'port': int(port.get('port') or 0),
                'protocol': str(port.get('protocol') or ''),
                'state': str(port.get('state') or ''),
                'service': str(port.get('service') or ''),
                'product': str(port.get('product') or ''),
                'version': str(port.get('version') or ''),
            })
        ports.sort(key=lambda item: (item['protocol'], item['port']))
        hosts.append({'ip': str(host.get('ip') or ''), 'ports': ports})
    hosts.sort(key=lambda item: item['ip'])
    return {
        'hosts': hosts,
        'host_count': len(hosts),
        'open_ports': sum(1 for host in hosts for port in host['ports'] if port['state'] == 'open'),
    }


def compare_nmap_semantics(legacy_xml: str, candidate_xml: str) -> dict[str, Any]:
    legacy = nmap_semantic_snapshot(legacy_xml)
    candidate = nmap_semantic_snapshot(candidate_xml)
    return {
        'schema': 'aegis.network-nmap-semantic-parity.v1',
        'equivalent': legacy == candidate,
        'legacy': legacy,
        'candidate': candidate,
    }
