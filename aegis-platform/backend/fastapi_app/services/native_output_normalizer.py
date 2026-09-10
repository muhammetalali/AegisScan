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
    # Only literal IPs belong in transport evidence, never arbitrary strings,
    # numeric coercions, or IPv6 zone identifiers that may carry other data.
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


def normalize_native_output(capability_id: str, stdout: str) -> dict[str, Any]:
    """Convert stable tool output formats into bounded AegisScan observations."""
    raw = stdout or ''
    observations: list[dict[str, Any]] = []

    if capability_id == 'web.ffuf':
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
