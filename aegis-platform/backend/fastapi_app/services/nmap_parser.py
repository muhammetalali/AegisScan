from defusedxml import ElementTree as ET


def parse_nmap_xml(raw_xml: str) -> dict:
    root = ET.fromstring(raw_xml)
    hosts = []
    for host in root.findall('host'):
        address = host.find('address')
        ip = address.get('addr') if address is not None else None
        ports = []
        for port in host.findall('./ports/port'):
            state = port.find('state')
            service = port.find('service')
            ports.append({
                'port': int(port.get('portid', '0')),
                'protocol': port.get('protocol'),
                'state': state.get('state') if state is not None else None,
                'service': service.get('name') if service is not None else None,
                'product': service.get('product') if service is not None else None,
                'version': service.get('version') if service is not None else None,
            })
        hosts.append({'ip': ip, 'ports': ports})
    return {'hosts': hosts, 'host_count': len(hosts), 'open_ports': sum(1 for h in hosts for p in h['ports'] if p['state'] == 'open')}
