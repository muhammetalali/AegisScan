from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

from .native_output_normalizer import normalize_native_output as _base_normalize_native_output

_ENRICHMENT_SCHEMA = 'aegis.js-parameter-enrichment.v1'
_ALLOWED_URL_SCHEMES = {'http', 'https', 'ws', 'wss'}
_PARAMETER_RE = re.compile(r'^[A-Za-z0-9_$.-](?:[A-Za-z0-9_$.[\]-]{0,198}[A-Za-z0-9_$\]]|[A-Za-z0-9_$.-]?)$')
_MAX_PARAMETERS = 512
_MAX_OBSERVATIONS = 2000


def _safe_parameter_name(value: Any) -> str | None:
    name = str(value or '').strip()
    if not name or len(name) > 200 or any(ch in name for ch in '\r\n\x00'):
        return None
    if not _PARAMETER_RE.fullmatch(name):
        return None
    return name


def _parameter_names(values: Any, *, limit: int = 128) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    result: set[str] = set()
    for value in list(values)[: limit * 2]:
        name = _safe_parameter_name(value)
        if name is not None:
            result.add(name)
        if len(result) >= limit:
            break
    return sorted(result)


def _redacted_url(value: Any) -> tuple[str, list[str]]:
    raw = str(value or '').strip()
    if not raw or len(raw) > 8192 or any(ch in raw for ch in '\r\n\x00'):
        return '', []
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        return '', []
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme not in _ALLOWED_URL_SCHEMES or not host or parsed.username is not None or parsed.password is not None:
        return '', []
    default_port = 80 if scheme in {'http', 'ws'} else 443
    authority = host if port in {None, default_port} else f'{host}:{port}'
    names: set[str] = set()
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256)
    except ValueError:
        return '', []
    for raw_name, _raw_value in pairs:
        name = _safe_parameter_name(raw_name)
        if name is not None:
            names.add(name)
        if len(names) >= 128:
            break
    query = '&'.join(f'{quote(name, safe="[]$_.-")}=*' for name in sorted(names))
    path = parsed.path or '/'
    return urlunsplit((scheme, authority, path[:2048], query, '')), sorted(names)


def _json_lines(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in (raw or '').splitlines()[:5000]:
        line = line.strip()
        if not line or len(line) > 2 * 1024 * 1024:
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _positive_int(value: Any, maximum: int = 2_147_483_647) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return parsed if 0 <= parsed <= maximum else 0


def _bounded_strings(value: Any, *, limit: int, item_limit: int = 500) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value[:limit]:
        text = str(item or '').strip()
        if text and '\x00' not in text:
            result.append(text[:item_limit])
    return result


def _normalize_httpx(raw: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _json_lines(raw):
        url, parameters = _redacted_url(item.get('url') or item.get('input'))
        if not url or url in seen:
            continue
        seen.add(url)
        technologies = item.get('tech') if isinstance(item.get('tech'), list) else item.get('technologies')
        observation: dict[str, Any] = {
            'kind': 'web-http-service',
            'url': url,
            'query_parameter_names': parameters,
            'status': _positive_int(item.get('status_code') or item.get('status-code'), 599),
            'title': str(item.get('title') or '')[:500],
            'content_type': str(item.get('content_type') or item.get('content-type') or '')[:200],
            'webserver': str(item.get('webserver') or '')[:200],
            'technologies': _bounded_strings(technologies, limit=64, item_limit=200),
            'discovery_source': 'httpx',
        }
        observations.append(observation)
        if len(observations) >= _MAX_OBSERVATIONS - 1:
            break
    return observations


def _katana_endpoint(item: dict[str, Any]) -> tuple[str, str, int, str]:
    request = item.get('request') if isinstance(item.get('request'), dict) else {}
    response = item.get('response') if isinstance(item.get('response'), dict) else {}
    raw_url = (
        request.get('endpoint')
        or request.get('url')
        or item.get('endpoint')
        or item.get('url')
        or ''
    )
    method = str(request.get('method') or item.get('method') or 'GET').upper()[:16]
    status = _positive_int(response.get('status_code') or item.get('status_code'), 599)
    tag = str(item.get('tag') or request.get('tag') or '')[:100]
    return str(raw_url), method, status, tag


def _normalize_katana(raw: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in _json_lines(raw):
        raw_url, method, status, tag = _katana_endpoint(item)
        url, parameters = _redacted_url(raw_url)
        if not url:
            continue
        key = (method, url)
        if key in seen:
            continue
        seen.add(key)
        path = urlsplit(url).path.lower()
        javascript = path.endswith(('.js', '.mjs', '.cjs')) or tag.lower() in {'script', 'js'}
        observation: dict[str, Any] = {
            'kind': 'web-javascript-resource' if javascript else 'web-discovered-endpoint',
            'url': url,
            'method': method,
            'status': status,
            'query_parameter_names': parameters,
            'discovery_source': 'katana',
        }
        if tag:
            observation['tag'] = tag
        observations.append(observation)
        if len(observations) >= _MAX_OBSERVATIONS - 1:
            break
    return observations


def _parameter_surface(observations: list[dict[str, Any]], *, source_family: str) -> dict[str, Any] | None:
    catalog: dict[str, dict[str, set[str]]] = {}
    javascript_resources = 0
    source_maps = 0

    def add(name: Any, source: str, location_kind: str) -> None:
        safe = _safe_parameter_name(name)
        if safe is None:
            return
        entry = catalog.setdefault(safe, {'sources': set(), 'location_kinds': set()})
        entry['sources'].add(source)
        entry['location_kinds'].add(location_kind)

    for item in observations:
        if not isinstance(item, dict):
            continue
        kind = str(item.get('kind') or '')
        for name in _parameter_names(item.get('query_parameter_names'), limit=128):
            add(name, 'query', kind)
        for name in _parameter_names(item.get('body_parameter_names'), limit=128):
            add(name, 'body', kind)
        if kind == 'browser-graphql-operation':
            for name in _parameter_names(item.get('variable_keys'), limit=128):
                add(name, 'graphql-variable', kind)
        if kind in {'browser-javascript-resource', 'web-javascript-resource'}:
            javascript_resources += 1
            if item.get('source_map_url'):
                source_maps += 1
        if len(catalog) >= _MAX_PARAMETERS:
            break

    if not catalog and not javascript_resources:
        return None
    parameters = [
        {
            'name': name,
            'sources': sorted(entry['sources']),
            'location_kinds': sorted(entry['location_kinds']),
        }
        for name, entry in sorted(catalog.items())[:_MAX_PARAMETERS]
    ]
    return {
        'kind': 'parameter-surface-summary',
        'source_family': source_family,
        'parameter_count': len(parameters),
        'parameters': parameters,
        'javascript_resource_count': javascript_resources,
        'source_map_count': source_maps,
        'values_persisted': False,
    }


def _enrich_browser_observations(base: dict[str, Any]) -> dict[str, Any]:
    raw_observations = base.get('observations') if isinstance(base.get('observations'), list) else []
    observations: list[dict[str, Any]] = []
    for raw in raw_observations[:_MAX_OBSERVATIONS]:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        kind = str(item.get('kind') or '')
        for field in ('url', 'endpoint', 'document_url', 'source_map_url'):
            if field not in item:
                continue
            canonical, names = _redacted_url(item.get(field))
            if canonical:
                item[field] = canonical
                if field in {'url', 'endpoint'} and names:
                    existing = _parameter_names(item.get('query_parameter_names'), limit=128)
                    item['query_parameter_names'] = sorted(set(existing) | set(names))[:128]
            else:
                item.pop(field, None)
        if kind == 'browser-graphql-operation':
            item['variable_keys'] = _parameter_names(item.get('variable_keys'), limit=100)
        observations.append(item)
    summary = _parameter_surface(observations, source_family='browser-spa')
    if summary is not None and len(observations) < _MAX_OBSERVATIONS:
        observations.append(summary)
    return {
        **base,
        'count': len(observations),
        'observations': observations,
        'enrichment': {
            'schema': _ENRICHMENT_SCHEMA,
            'values_persisted': False,
            'source_family': 'browser-spa',
        },
    }


def normalize_enriched_native_output(capability_id: str, stdout: str) -> dict[str, Any]:
    if capability_id == 'web.httpx':
        observations = _normalize_httpx(stdout)
        summary = _parameter_surface(observations, source_family='httpx')
        if summary is not None and len(observations) < _MAX_OBSERVATIONS:
            observations.append(summary)
        return {
            'schema': 'aegis.native-observations.v1',
            'count': len(observations),
            'observations': observations,
            'enrichment': {'schema': _ENRICHMENT_SCHEMA, 'values_persisted': False, 'source_family': 'httpx'},
        }
    if capability_id == 'web.katana':
        observations = _normalize_katana(stdout)
        summary = _parameter_surface(observations, source_family='katana')
        if summary is not None and len(observations) < _MAX_OBSERVATIONS:
            observations.append(summary)
        return {
            'schema': 'aegis.native-observations.v1',
            'count': len(observations),
            'observations': observations,
            'enrichment': {'schema': _ENRICHMENT_SCHEMA, 'values_persisted': False, 'source_family': 'katana'},
        }

    base = _base_normalize_native_output(capability_id, stdout)
    if capability_id == 'browser.spa-discovery':
        return _enrich_browser_observations(base)
    return base
