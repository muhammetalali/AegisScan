from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit


def _json(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def _bounded(items: list[dict[str, Any]], limit: int = 2000) -> list[dict[str, Any]]:
    return items[:limit]


def normalize_native_output(capability_id: str, stdout: str) -> dict[str, Any]:
    """Convert stable tool output formats into bounded AegisScan observations.

    Raw scanner output remains the evidence source of truth. Normalized values
    are derived metadata for correlation and UI consumption, never a substitute
    for the immutable raw evidence and SHA-256 digest.
    """
    raw = stdout or ''
    observations: list[dict[str, Any]] = []

    if capability_id == 'web.ffuf':
        data = _json(raw)
        for item in data.get('results', []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            url = str(item.get('url') or '')[:2048]
            observations.append({
                'kind': 'web-endpoint',
                'url': url,
                'status': int(item.get('status') or 0),
                'length': int(item.get('length') or 0),
                'words': int(item.get('words') or 0),
                'lines': int(item.get('lines') or 0),
            })

    elif capability_id == 'web.gobuster':
        pattern = re.compile(r'^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s+\[Size:\s*(?P<size>\d+)\])?')
        for line in raw.splitlines():
            match = pattern.search(line.strip())
            if not match:
                continue
            observations.append({
                'kind': 'web-path',
                'path': match.group('path')[:2048],
                'status': int(match.group('status')),
                'length': int(match.group('size') or 0),
            })

    elif capability_id == 'forensics.exiftool':
        data = _json(raw)
        records = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        for item in records:
            if not isinstance(item, dict):
                continue
            safe = {
                str(key)[:100]: value
                for key, value in item.items()
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

    elif capability_id in {'binary.checksec', 'binary.strings', 'binary.objdump', 'binary.readelf', 'binary.binwalk'}:
        nonempty = [line.strip() for line in raw.splitlines() if line.strip()]
        observations.append({
            'kind': 'binary-analysis-summary',
            'line_count': len(nonempty),
            'preview': nonempty[:50],
        })

    return {
        'schema': 'aegis.native-observations.v1',
        'count': min(len(observations), 2000),
        'observations': _bounded(observations),
    }
