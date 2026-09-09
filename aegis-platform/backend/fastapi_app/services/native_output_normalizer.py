from __future__ import annotations

import json
import re
from typing import Any


def _json(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _json_lines(value: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in (value or '').splitlines():
        item = _json(line.strip())
        if isinstance(item, dict):
            records.append(item)
    return records


def _bounded(items: list[dict[str, Any]], limit: int = 2000) -> list[dict[str, Any]]:
    return items[:limit]


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _katana_url(item: dict[str, Any]) -> str:
    for key in ('url', 'endpoint'):
        value = item.get(key)
        if isinstance(value, str) and value.startswith(('http://', 'https://')):
            return value
    request = item.get('request')
    if isinstance(request, dict):
        for key in ('endpoint', 'url'):
            value = request.get(key)
            if isinstance(value, str) and value.startswith(('http://', 'https://')):
                return value
    return ''


def normalize_native_output(capability_id: str, stdout: str) -> dict[str, Any]:
    """Convert stable tool output formats into bounded AegisScan observations."""
    raw = stdout or ''
    observations: list[dict[str, Any]] = []

    if capability_id == 'network.rustscan':
        seen: set[tuple[str, int]] = set()
        open_pattern = re.compile(r'^\s*Open\s+(?P<host>[^\s:]+):(?P<port>\d{1,5})\s*$', re.I)
        ports_pattern = re.compile(r'^\s*(?P<ports>\d{1,5}(?:\s*,\s*\d{1,5})*)\s*$')
        for line in raw.splitlines():
            match = open_pattern.match(line)
            if match:
                port = _safe_int(match.group('port'))
                if 1 <= port <= 65535:
                    key = (match.group('host'), port)
                    if key not in seen:
                        seen.add(key)
                        observations.append({
                            'kind': 'open-port', 'host': match.group('host')[:255],
                            'port': port, 'protocol': 'tcp',
                        })
                continue
            match = ports_pattern.match(line)
            if not match:
                continue
            for token in match.group('ports').split(','):
                port = _safe_int(token.strip())
                key = ('', port)
                if 1 <= port <= 65535 and key not in seen:
                    seen.add(key)
                    observations.append({'kind': 'open-port', 'port': port, 'protocol': 'tcp'})

    elif capability_id == 'web.ffuf':
        data = _json(raw)
        for item in data.get('results', []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            observations.append({
                'kind': 'web-endpoint',
                'url': str(item.get('url') or '')[:2048],
                'status': _safe_int(item.get('status')),
                'length': _safe_int(item.get('length')),
                'words': _safe_int(item.get('words')),
                'lines': _safe_int(item.get('lines')),
            })

    elif capability_id == 'web.katana':
        for item in _json_lines(raw):
            url = _katana_url(item)
            if not url:
                continue
            response = item.get('response') if isinstance(item.get('response'), dict) else {}
            observations.append({
                'kind': 'web-endpoint',
                'url': url[:2048],
                'method': str((item.get('request') or {}).get('method') or item.get('method') or 'GET')[:16]
                if isinstance(item.get('request'), dict) else str(item.get('method') or 'GET')[:16],
                'status': _safe_int(response.get('status_code') or response.get('status') or item.get('status_code') or item.get('status')),
            })

    elif capability_id == 'web.feroxbuster':
        for item in _json_lines(raw):
            url = item.get('url')
            if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                continue
            observations.append({
                'kind': 'web-endpoint',
                'url': url[:2048],
                'status': _safe_int(item.get('status') or item.get('status_code')),
                'length': _safe_int(item.get('content_length') or item.get('length')),
                'method': str(item.get('method') or 'GET')[:16],
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

    elif capability_id == 'web.nikto':
        data = _json(raw)
        records = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        for record in records:
            if not isinstance(record, dict):
                continue
            host = str(record.get('host') or '')[:255]
            port = _safe_int(record.get('port'))
            findings = record.get('vulnerabilities')
            if not isinstance(findings, list):
                findings = [record] if any(key in record for key in ('id', 'msg', 'url')) else []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                message = str(finding.get('msg') or finding.get('message') or '').strip()
                path = str(finding.get('url') or finding.get('path') or '').strip()
                if not message and not path:
                    continue
                observations.append({
                    'kind': 'web-security-observation',
                    'id': str(finding.get('id') or '')[:128],
                    'host': host,
                    'port': port,
                    'method': str(finding.get('method') or 'GET')[:16],
                    'path': path[:2048],
                    'message': message[:4000],
                    'references': str(finding.get('references') or '')[:4000],
                })

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
