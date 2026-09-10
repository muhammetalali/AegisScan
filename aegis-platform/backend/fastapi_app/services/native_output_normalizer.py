from __future__ import annotations

import json
import ipaddress
import re
from typing import Any


def _json(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _bounded(items: list[dict[str, Any]], limit: int = 2000) -> list[dict[str, Any]]:
    return items[:limit]


def _normalize_headers(raw: str) -> list[dict[str, Any]]:
    required_security_headers = {
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'referrer-policy',
        'permissions-policy',
    }
    observations: list[dict[str, Any]] = []
    current_status = 0
    headers: dict[str, str] = {}

    def flush() -> None:
        nonlocal current_status, headers
        if not current_status and not headers:
            return
        present = sorted(required_security_headers & set(headers))
        observations.append({
            'kind': 'web-response-headers',
            'status': current_status,
            'headers': dict(sorted(headers.items())) if len(headers) <= 100 else dict(sorted(headers.items())[:100]),
            'present_security_headers': present,
            'missing_security_headers': sorted(required_security_headers - set(headers)),
        })
        current_status = 0
        headers = {}

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            flush()
            continue
        if stripped.startswith('HTTP/'):
            flush()
            parts = stripped.split()
            try:
                current_status = int(parts[1])
            except (IndexError, ValueError):
                current_status = 0
            continue
        if ':' not in stripped:
            continue
        name, value = stripped.split(':', 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or len(name) > 100:
            continue
        headers[name] = value[:2048]
    flush()
    return observations


def _normalize_api_observations(data: dict[str, Any], fallback_kind: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in data.get('observations', []) if isinstance(data.get('observations'), list) else []:
        if not isinstance(item, dict):
            continue
        safe = dict(item)
        safe['kind'] = str(safe.get('kind') or fallback_kind)[:100]
        for key in (
            'title', 'description', 'remediation', 'location', 'path', 'spec_url',
            'parameter', 'reason', 'error', 'content_type', 'auth_mode',
        ):
            if key in safe:
                safe[key] = str(safe[key])[:4096]
        if isinstance(safe.get('affected_urls'), list):
            safe['affected_urls'] = [str(value)[:2048] for value in safe['affected_urls'][:20]]
        if isinstance(safe.get('validation_errors'), list):
            safe['validation_errors'] = [str(value)[:500] for value in safe['validation_errors'][:20]]
        if isinstance(safe.get('synthetic_inputs'), list):
            safe['synthetic_inputs'] = [str(value)[:200] for value in safe['synthetic_inputs'][:50]]
        result.append(safe)
    return result


def _normalized_ip(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 45 or '%' in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _normalize_kubernetes_observations(data: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    observations = data.get('observations') if isinstance(data.get('observations'), list) else []
    for item in observations[:2000]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get('kind') or 'kubernetes-observation')[:100]
        safe: dict[str, Any] = {'kind': kind}
        for key in (
            'rule_id', 'title', 'description', 'remediation', 'severity', 'confidence',
            'category', 'location', 'namespace', 'resource_kind', 'resource_name', 'container',
            'cwe_id', 'owasp_category', 'server', 'git_version',
        ):
            if key in item:
                safe[key] = str(item.get(key) or '')[:4096]
        for key in (
            'namespace_count', 'pod_count', 'deployment_count', 'clusterrole_count',
            'clusterrolebinding_count', 'finding_count', 'coverage_gaps', 'truncated_collections',
        ):
            if key in item:
                try:
                    safe[key] = max(0, int(item.get(key) or 0))
                except (TypeError, ValueError):
                    safe[key] = 0
        for key in ('read_only', 'secrets_endpoint_requested'):
            if key in item:
                safe[key] = bool(item.get(key))
        if 'dns_pinned_for_scan' in item:
            safe['dns_pinned_for_scan'] = item['dns_pinned_for_scan'] is True
        if isinstance(item.get('pinned_destination_ips'), list):
            safe['pinned_destination_ips'] = list(dict.fromkeys(
                address for value in item['pinned_destination_ips'][:64]
                if (address := _normalized_ip(value)) is not None
            ))
        if isinstance(item.get('requested_paths'), list):
            safe['requested_paths'] = [str(value)[:512] for value in item['requested_paths'][:20]]
        if isinstance(item.get('coverage'), list):
            coverage: list[dict[str, Any]] = []
            for entry in item['coverage'][:20]:
                if not isinstance(entry, dict):
                    continue
                try:
                    status = int(entry.get('status') or 0)
                except (TypeError, ValueError):
                    status = 0
                coverage.append({
                    'path': str(entry.get('path') or '')[:512],
                    'status': status,
                    'accessible': bool(entry.get('accessible')),
                    'truncated': bool(entry.get('truncated')),
                })
                address = _normalized_ip(entry.get('resolved_ip'))
                if address is not None:
                    coverage[-1]['resolved_ip'] = address
            safe['coverage'] = coverage
        result.append(safe)
    return result


def _normalize_cloud_observations(data: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    observations = data.get('observations') if isinstance(data.get('observations'), list) else []
    for item in observations[:2000]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get('kind') or 'cloud-observation')[:100]
        safe: dict[str, Any] = {'kind': kind}
        for key in (
            'provider', 'target', 'rule_id', 'title', 'description', 'remediation',
            'severity', 'confidence', 'category', 'location', 'resource_kind', 'resource_name',
        ):
            if key in item:
                safe[key] = str(item.get(key) or '')[:4096]
        for key in ('identity_verified', 'read_only', 'ambient_credentials_used'):
            if key in item:
                safe[key] = item.get(key) is True
        if 'finding_count' in item:
            try:
                safe['finding_count'] = max(0, int(item.get('finding_count') or 0))
            except (TypeError, ValueError):
                safe['finding_count'] = 0
        inventory = item.get('inventory')
        if isinstance(inventory, dict):
            safe_inventory: dict[str, Any] = {}
            for key, value in list(inventory.items())[:50]:
                name = str(key)[:100]
                if isinstance(value, bool) or value is None:
                    safe_inventory[name] = value
                elif isinstance(value, int):
                    safe_inventory[name] = max(0, value)
                elif isinstance(value, str):
                    safe_inventory[name] = value[:1000]
            safe['inventory'] = safe_inventory
        gaps = item.get('coverage_gaps')
        if isinstance(gaps, list):
            safe['coverage_gaps'] = [
                {
                    'provider': str(entry.get('provider') or '')[:20],
                    'operation': str(entry.get('operation') or '')[:200],
                    'code': str(entry.get('code') or '')[:100],
                }
                for entry in gaps[:100]
                if isinstance(entry, dict)
            ]
        if 'credential_source' in item:
            safe['credential_source'] = str(item.get('credential_source') or '')[:100]
        result.append(safe)
    return result


def _json_lines(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in raw.splitlines():
        value = _json(line.strip())
        if isinstance(value, dict):
            records.append(value)
    return records


def _embedded_json(raw: str) -> Any:
    decoder = json.JSONDecoder()
    for index, char in enumerate(raw):
        if char not in '[{':
            continue
        try:
            value, _ = decoder.raw_decode(raw[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, (dict, list)):
            return value
    return None


def _positive_int(value: Any, maximum: int = 2_147_483_647) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if 0 <= parsed <= maximum else 0


def _normalize_rustscan(raw: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen_open: set[tuple[str, int]] = set()
    open_pattern = re.compile(r'^Open\s+(?P<host>\[[^\]]+\]|[^:\s]+):(?P<port>\d{1,5})\s*$', re.I)
    nmap_pattern = re.compile(
        r'^(?P<port>\d{1,5})/(?P<protocol>tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$',
        re.I,
    )
    for line in raw.splitlines():
        stripped = line.strip()
        match = open_pattern.match(stripped)
        if match:
            port = _positive_int(match.group('port'), 65535)
            if not 1 <= port <= 65535:
                continue
            host = match.group('host').strip('[]')[:253]
            key = (host, port)
            if key in seen_open:
                continue
            seen_open.add(key)
            observations.append({
                'kind': 'network-open-port',
                'host': host,
                'port': port,
                'protocol': 'tcp',
                'service': '',
                'version': '',
            })
            continue
        match = nmap_pattern.match(stripped)
        if not match:
            continue
        port = _positive_int(match.group('port'), 65535)
        if not 1 <= port <= 65535:
            continue
        observations.append({
            'kind': 'network-service',
            'port': port,
            'protocol': (match.group('protocol') or 'tcp').lower(),
            'service': (match.group('service') or '')[:100],
            'version': (match.group('version') or '')[:1000],
        })
    return observations


def _normalize_amass(raw: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    host_pattern = re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b')
    ignored = {
        'github.com', 'discord.com', 'owasp.org', 'golang.org',
        'projectdiscovery.io', 'skerritt.blog',
    }
    seen: set[str] = set()
    for line in raw.splitlines():
        lowered = line.lower()
        if 'discord server' in lowered or 'usage:' in lowered:
            continue
        for match in host_pattern.findall(line):
            hostname = match.rstrip('.').lower()
            if hostname in ignored or hostname in seen:
                continue
            seen.add(hostname)
            observations.append({'kind': 'discovered-hostname', 'hostname': hostname})
    return observations


def _normalize_feroxbuster(raw: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for item in _json_lines(raw):
        if str(item.get('type') or '').lower() != 'response':
            continue
        url = str(item.get('url') or '')[:2048]
        if not url.startswith(('http://', 'https://')):
            continue
        observations.append({
            'kind': 'web-endpoint',
            'url': url,
            'path': str(item.get('path') or '')[:2048],
            'status': _positive_int(item.get('status'), 599),
            'length': _positive_int(item.get('content_length')),
            'words': _positive_int(item.get('word_count')),
            'lines': _positive_int(item.get('line_count')),
            'method': str(item.get('method') or 'GET').upper()[:16],
        })
    return observations


def _normalize_nikto(raw: str) -> list[dict[str, Any]]:
    data = _embedded_json(raw)
    reports = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    observations: list[dict[str, Any]] = []
    for report in reports[:100]:
        if not isinstance(report, dict):
            continue
        host = str(report.get('host') or '')[:253]
        ip = str(report.get('ip') or '')[:64]
        port = _positive_int(report.get('port'), 65535)
        vulnerabilities = report.get('vulnerabilities')
        if isinstance(vulnerabilities, list) and vulnerabilities:
            for item in vulnerabilities[:2000]:
                if not isinstance(item, dict):
                    continue
                message = str(item.get('msg') or '').strip()[:5000]
                rule = str(item.get('id') or 'unknown').strip()[:100]
                uri = str(item.get('url') or '').strip()[:2048]
                refs = item.get('references')
                observations.append({
                    'kind': 'web-vulnerability',
                    'rule_id': f'nikto.{rule}',
                    'title': (message[:500] or f'Nikto finding {rule}'),
                    'description': message or 'Nikto reported a web-server security observation.',
                    'severity': 'medium',
                    'confidence': 'medium',
                    'category': 'web-vulnerability-assessment',
                    'host': host,
                    'ip': ip,
                    'port': port,
                    'location': uri,
                    'method': str(item.get('method') or 'GET').upper()[:16],
                    'references': [str(value)[:2048] for value in refs[:20]] if isinstance(refs, list) else [],
                    'remediation': 'Review the affected web-server configuration or resource and remove the reported exposure.',
                })
        else:
            observations.append({
                'kind': 'web-scan-summary',
                'host': host,
                'ip': ip,
                'port': port,
                'finding_count': 0,
            })
    return observations


def _normalize_trivy_config(raw: str) -> list[dict[str, Any]]:
    data = _json(raw)
    if not isinstance(data, dict):
        data = _embedded_json(raw)
    if not isinstance(data, dict):
        return []
    observations: list[dict[str, Any]] = []
    results = data.get('Results')
    for result in results[:500] if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        target = str(result.get('Target') or '')[:2048]
        klass = str(result.get('Class') or '')[:100]
        result_type = str(result.get('Type') or '')[:100]
        items = result.get('Misconfigurations')
        for item in items[:2000] if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            status = str(item.get('Status') or '').upper()
            if status and status not in {'FAIL', 'FAILURE'}:
                continue
            rule_id = str(item.get('AVDID') or item.get('ID') or '').strip()[:200]
            title = str(item.get('Title') or item.get('Message') or rule_id or 'IaC misconfiguration').strip()[:500]
            description = str(item.get('Description') or item.get('Message') or title).strip()[:5000]
            severity = str(item.get('Severity') or 'UNKNOWN').lower()
            if severity not in {'critical', 'high', 'medium', 'low', 'unknown'}:
                severity = 'unknown'
            cause = item.get('CauseMetadata') if isinstance(item.get('CauseMetadata'), dict) else {}
            start_line = _positive_int(cause.get('StartLine'))
            location = target + (f':{start_line}' if start_line else '')
            refs = item.get('References')
            observations.append({
                'kind': 'iac-security-finding',
                'rule_id': rule_id or 'trivy.unknown',
                'title': title,
                'description': description,
                'severity': 'info' if severity == 'unknown' else severity,
                'confidence': 'high',
                'category': 'iac-security',
                'location': location[:2048],
                'resource': str(cause.get('Resource') or '')[:1000],
                'remediation': str(item.get('Resolution') or item.get('RecommendedActions') or '')[:5000],
                'references': [str(value)[:2048] for value in refs[:20]] if isinstance(refs, list) else [],
                'primary_url': str(item.get('PrimaryURL') or '')[:2048],
                'class': klass,
                'type': result_type,
            })
    return observations


def normalize_native_output(capability_id: str, stdout: str) -> dict[str, Any]:
    """Convert stable tool output formats into bounded AegisScan observations."""
    raw = stdout or ''
    observations: list[dict[str, Any]] = []

    if capability_id == 'network.rustscan':
        observations.extend(_normalize_rustscan(raw))

    elif capability_id == 'recon.amass':
        observations.extend(_normalize_amass(raw))

    elif capability_id == 'web.feroxbuster':
        observations.extend(_normalize_feroxbuster(raw))

    elif capability_id == 'web.nikto':
        observations.extend(_normalize_nikto(raw))

    elif capability_id == 'code.trivy-config':
        observations.extend(_normalize_trivy_config(raw))

    elif capability_id == 'web.ffuf':
        data = _json(raw)
        for item in data.get('results', []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            observations.append({
                'kind': 'web-endpoint',
                'url': str(item.get('url') or '')[:2048],
                'status': int(item.get('status') or 0),
                'length': int(item.get('length') or 0),
                'words': int(item.get('words') or 0),
                'lines': int(item.get('lines') or 0),
            })

    elif capability_id == 'web.gobuster':
        pattern = re.compile(r'^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s+\[Size:\s*(?P<size>\d+)\])?')
        for line in raw.splitlines():
            match = pattern.search(line.strip())
            if match:
                observations.append({
                    'kind': 'web-path', 'path': match.group('path')[:2048],
                    'status': int(match.group('status')), 'length': int(match.group('size') or 0),
                })

    elif capability_id == 'web.dirb':
        pattern = re.compile(r'^(?:\+|==>)\s+(?P<url>https?://\S+).*?(?:CODE:(?P<status>\d{3})|\((?P<status2>\d{3})\))?', re.I)
        for line in raw.splitlines():
            match = pattern.search(line.strip())
            if match:
                observations.append({
                    'kind': 'web-endpoint',
                    'url': match.group('url')[:2048],
                    'status': int(match.group('status') or match.group('status2') or 0),
                })

    elif capability_id == 'web.security-headers':
        observations.extend(_normalize_headers(raw))

    elif capability_id == 'browser.dom-snapshot':
        data = _json(raw)
        if isinstance(data, dict):
            for item in data.get('observations', []):
                if isinstance(item, dict):
                    safe = dict(item)
                    safe['kind'] = str(safe.get('kind') or 'browser-dom-security-snapshot')[:100]
                    observations.append(safe)
            if not observations and data.get('error'):
                observations.append({'kind': 'browser-error', 'summary': str(data['error'])[:2000]})

    elif capability_id == 'api.openapi-contract-security':
        data = _json(raw)
        if isinstance(data, dict):
            observations.extend(_normalize_api_observations(data, 'api-schema-observation'))
            if not observations and data.get('error'):
                observations.append({'kind': 'api-schema-error', 'summary': str(data['error'])[:2000]})

    elif capability_id == 'api.openapi-runtime-conformance':
        data = _json(raw)
        if isinstance(data, dict):
            observations.extend(_normalize_api_observations(data, 'api-runtime-observation'))
            if not observations and data.get('error'):
                observations.append({'kind': 'api-runtime-error', 'summary': str(data['error'])[:2000]})

    elif capability_id == 'kubernetes.read-only-posture':
        data = _json(raw)
        if isinstance(data, dict):
            observations.extend(_normalize_kubernetes_observations(data))
            if not observations and data.get('error'):
                observations.append({'kind': 'kubernetes-error', 'summary': str(data['error'])[:2000]})

    elif capability_id == 'cloud.read-only-posture':
        data = _json(raw)
        if isinstance(data, dict):
            observations.extend(_normalize_cloud_observations(data))
            if not observations and data.get('error'):
                observations.append({'kind': 'cloud-error', 'summary': str(data['error'])[:2000]})

    elif capability_id == 'forensics.exiftool':
        data = _json(raw)
        records = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        for item in records:
            if isinstance(item, dict):
                safe = {
                    str(key)[:100]: value for key, value in item.items()
                    if isinstance(value, (str, int, float, bool)) or value is None
                }
                observations.append({'kind': 'file-metadata', 'attributes': safe})

    elif capability_id == 'web.waf-detection':
        lowered = raw.lower()
        if 'is behind' in lowered or 'identified' in lowered or 'waf' in lowered:
            observations.append({'kind': 'web-control-fingerprint', 'summary': raw.strip()[:4000]})

    elif capability_id in {'recon.dnsenum', 'recon.fierce'}:
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        host_pattern = re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b')
        seen: set[tuple[str, str]] = set()
        for line in raw.splitlines():
            for value in ip_pattern.findall(line):
                key = ('ip', value)
                if key not in seen:
                    seen.add(key)
                    observations.append({'kind': 'dns-address', 'value': value})
            for value in host_pattern.findall(line):
                value = value.rstrip('.').lower()
                key = ('hostname', value)
                if key not in seen:
                    seen.add(key)
                    observations.append({'kind': 'dns-hostname', 'value': value})

    elif capability_id in {'network.nbtscan-host', 'network.nbtscan-range'}:
        pattern = re.compile(r'^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<name>\S+)(?:\s+(?P<service>\S+))?')
        for line in raw.splitlines():
            match = pattern.search(line)
            if match:
                observations.append({
                    'kind': 'netbios-host', 'ip': match.group('ip'),
                    'name': match.group('name')[:255], 'service': (match.group('service') or '')[:255],
                })

    elif capability_id in {
        'binary.checksec', 'binary.strings', 'binary.objdump', 'binary.readelf',
        'binary.xxd', 'binary.gdb-metadata', 'binary.binwalk',
    }:
        nonempty = [line.strip() for line in raw.splitlines() if line.strip()]
        observations.append({
            'kind': 'binary-analysis-summary', 'line_count': len(nonempty), 'preview': nonempty[:50],
        })

    return {
        'schema': 'aegis.native-observations.v1',
        'count': min(len(observations), 2000),
        'observations': _bounded(observations),
    }
