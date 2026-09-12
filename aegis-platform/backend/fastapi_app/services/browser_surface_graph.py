from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from fastapi_app.services.web_security_foundation import upsert_graph_snapshot


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(str(value or '').strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or '').lower().rstrip('.')
        if scheme not in {'http', 'https', 'ws', 'wss'} or not host:
            return ''
        port = parsed.port
    except ValueError:
        return ''
    default = 80 if scheme in {'http', 'ws'} else 443
    authority = host if port in {None, default} else f'{host}:{port}'
    return urlunsplit((scheme, authority, '', '', ''))


def _graph_ref(prefix: str, value: str) -> str:
    raw = f'{prefix}:{value}'
    if len(raw) <= 480:
        return raw
    digest = hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()
    return f'{prefix}:sha256:{digest}'


def _first_summary(normalized: dict[str, Any]) -> dict[str, Any] | None:
    observations = normalized.get('observations') if isinstance(normalized, dict) else None
    if not isinstance(observations, list):
        return None
    for item in observations:
        if isinstance(item, dict) and item.get('kind') == 'browser-spa-summary':
            return item
    return None


def project_browser_surface_graph(*, scan: Any, normalized: dict[str, Any], evidence_ref: str) -> dict[str, Any]:
    summary = _first_summary(normalized)
    if summary is None:
        return {'nodes_created': 0, 'nodes_updated': 0, 'edges_created': 0, 'edges_updated': 0}

    project = scan.project
    observations = normalized.get('observations') if isinstance(normalized.get('observations'), list) else []
    identity_ref = str(summary.get('identity_ref') or 'anonymous')[:255]
    target_origin = str(summary.get('target_origin') or '')[:2048]
    provenance = {
        'source': 'browser.spa-discovery',
        'scan_id': str(scan.id),
        'evidence_ref': str(evidence_ref),
        'schema': 'aegis.browser-spa-discovery.v1',
    }
    evidence_refs = [str(evidence_ref)]

    asset_ref = f'asset:{scan.asset_id}'
    identity_node_ref = _graph_ref('identity', identity_ref)
    session_ref = _graph_ref('session', f'{scan.id}:{identity_ref}')
    capability_ref = 'capability:browser.spa-discovery'
    boundary_ref = _graph_ref('trust-boundary:browser-origin', target_origin)

    nodes: list[dict[str, Any]] = [
        {
            'plane': 'attack_surface',
            'kind': 'asset',
            'external_ref': asset_ref,
            'label': str(getattr(scan.asset, 'name', '') or scan.asset_id)[:300],
            'properties': {'asset_id': str(scan.asset_id)},
            'provenance': provenance,
        },
        {
            'plane': 'identity',
            'kind': 'identity',
            'external_ref': identity_node_ref,
            'label': identity_ref[:300],
            'properties': {'source': 'browser_identity_profile'},
            'provenance': provenance,
        },
        {
            'plane': 'identity',
            'kind': 'session',
            'external_ref': session_ref,
            'label': f'Browser session {identity_ref}'[:300],
            'protocol': 'browser',
            'properties': {
                'profile_isolation': str(summary.get('profile_isolation') or '')[:100],
                'credential_transport': str(summary.get('credential_transport') or '')[:100],
                'local_storage_keys': list(summary.get('local_storage_keys') or [])[:200],
                'session_storage_keys': list(summary.get('session_storage_keys') or [])[:200],
                'cookies': list(summary.get('cookies') or [])[:64],
            },
            'provenance': provenance,
        },
        {
            'plane': 'attack_surface',
            'kind': 'capability',
            'external_ref': capability_ref,
            'label': 'Browser SPA Discovery',
            'properties': {'capability_id': 'browser.spa-discovery'},
            'provenance': provenance,
        },
        {
            'plane': 'attack_surface',
            'kind': 'trust_boundary',
            'external_ref': boundary_ref,
            'label': target_origin[:300] or 'Browser target origin',
            'protocol': 'https' if target_origin.startswith('https://') else 'http',
            'properties': {'origin': target_origin},
            'provenance': provenance,
        },
    ]
    edges: list[dict[str, Any]] = [
        {
            'source_ref': identity_node_ref,
            'target_ref': session_ref,
            'relation': 'establishes',
            'properties': {},
            'evidence_refs': evidence_refs,
            'provenance': provenance,
        },
        {
            'source_ref': capability_ref,
            'target_ref': asset_ref,
            'relation': 'discovers',
            'properties': {},
            'evidence_refs': evidence_refs,
            'provenance': provenance,
        },
        {
            'source_ref': session_ref,
            'target_ref': boundary_ref,
            'relation': 'bound_to_origin',
            'properties': {'same_origin_credentials_only': True},
            'evidence_refs': evidence_refs,
            'provenance': provenance,
        },
    ]

    page_refs: list[str] = []
    endpoint_ref_by_key: dict[tuple[str, str], str] = {}
    external_service_refs: dict[str, str] = {}

    def ensure_external_service(url: str) -> str | None:
        origin = _origin(url)
        if not origin or origin == target_origin:
            return None
        existing = external_service_refs.get(origin)
        if existing:
            return existing
        ref = _graph_ref('external-service', origin)
        external_service_refs[origin] = ref
        nodes.append({
            'plane': 'attack_surface',
            'kind': 'external_service',
            'external_ref': ref,
            'label': origin[:300],
            'protocol': 'wss' if origin.startswith('wss://') else 'ws' if origin.startswith('ws://') else 'https' if origin.startswith('https://') else 'http',
            'properties': {'origin': origin},
            'provenance': provenance,
        })
        return ref

    for item in observations[:3000]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get('kind') or '')

        if kind == 'browser-page-route':
            url = str(item.get('url') or '')[:2048]
            if not url:
                continue
            ref = _graph_ref('page', url)
            if ref not in page_refs:
                page_refs.append(ref)
                nodes.append({
                    'plane': 'application',
                    'kind': 'page',
                    'external_ref': ref,
                    'label': url[:300],
                    'protocol': 'https' if url.startswith('https://') else 'http',
                    'properties': {'url': url},
                    'provenance': provenance,
                })
                edges.append({
                    'source_ref': asset_ref,
                    'target_ref': ref,
                    'relation': 'exposes',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
                edges.append({
                    'source_ref': session_ref,
                    'target_ref': ref,
                    'relation': 'observes',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
                if _origin(url) == target_origin:
                    edges.append({
                        'source_ref': ref,
                        'target_ref': boundary_ref,
                        'relation': 'inside_trust_boundary',
                        'properties': {},
                        'evidence_refs': evidence_refs,
                        'provenance': provenance,
                    })
            continue

        if kind == 'browser-http-endpoint':
            url = str(item.get('url') or '')[:2048]
            method = str(item.get('method') or 'GET').upper()[:16]
            if not url:
                continue
            ref = _graph_ref('endpoint', f'{method}:{url}')
            endpoint_ref_by_key[(method, url)] = ref
            nodes.append({
                'plane': 'application',
                'kind': 'endpoint',
                'external_ref': ref,
                'label': f'{method} {url}'[:300],
                'protocol': 'https' if url.startswith('https://') else 'http',
                'properties': {
                    'url': url,
                    'method': method,
                    'status': int(item.get('status') or 0),
                    'resource_type': str(item.get('resource_type') or '')[:80],
                    'mime_type': str(item.get('mime_type') or '')[:200],
                    'response_headers': item.get('response_headers') if isinstance(item.get('response_headers'), dict) else {},
                },
                'provenance': provenance,
            })
            service_ref = ensure_external_service(url)
            if service_ref:
                edges.append({
                    'source_ref': ref,
                    'target_ref': service_ref,
                    'relation': 'hosted_by',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
            else:
                edges.append({
                    'source_ref': ref,
                    'target_ref': boundary_ref,
                    'relation': 'inside_trust_boundary',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
            flow_ref = _graph_ref('data-flow', f'{session_ref}:{method}:{url}')
            nodes.append({
                'plane': 'attack_surface',
                'kind': 'data_flow',
                'external_ref': flow_ref,
                'label': f'{method} {url}'[:300],
                'protocol': 'https' if url.startswith('https://') else 'http',
                'properties': {'method': method, 'url': url, 'cross_origin': bool(service_ref)},
                'provenance': provenance,
            })
            edges.extend([
                {
                    'source_ref': session_ref,
                    'target_ref': flow_ref,
                    'relation': 'initiates_flow',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                },
                {
                    'source_ref': flow_ref,
                    'target_ref': ref,
                    'relation': 'flows_to',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                },
            ])
            continue

        if kind == 'browser-graphql-operation':
            endpoint = str(item.get('endpoint') or '')[:2048]
            method = str(item.get('method') or 'POST').upper()[:16]
            operation_type = str(item.get('operation_type') or '')[:32]
            operation_name = str(item.get('operation_name') or 'anonymous')[:200]
            gql_ref = _graph_ref(
                'graphql-operation',
                f'{endpoint}:{operation_type}:{operation_name}',
            )
            nodes.append({
                'plane': 'application',
                'kind': 'graphql_operation',
                'external_ref': gql_ref,
                'label': f'{operation_type} {operation_name}'[:300],
                'protocol': 'graphql',
                'properties': {
                    'endpoint': endpoint,
                    'method': method,
                    'operation_type': operation_type,
                    'operation_name': operation_name,
                    'variable_keys': list(item.get('variable_keys') or [])[:100],
                },
                'provenance': provenance,
            })
            endpoint_ref = endpoint_ref_by_key.get((method, endpoint))
            if endpoint_ref:
                edges.append({
                    'source_ref': endpoint_ref,
                    'target_ref': gql_ref,
                    'relation': 'accepts_operation',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
            continue

        if kind == 'browser-websocket-channel':
            url = str(item.get('url') or '')[:2048]
            if not url:
                continue
            ws_ref = _graph_ref('websocket-channel', url)
            nodes.append({
                'plane': 'application',
                'kind': 'websocket_channel',
                'external_ref': ws_ref,
                'label': url[:300],
                'protocol': 'wss' if url.startswith('wss://') else 'ws',
                'properties': {'url': url, 'cross_origin': _origin(url) != target_origin},
                'provenance': provenance,
            })
            edges.append({
                'source_ref': session_ref,
                'target_ref': ws_ref,
                'relation': 'opens_channel',
                'properties': {},
                'evidence_refs': evidence_refs,
                'provenance': provenance,
            })
            service_ref = ensure_external_service(url)
            if service_ref:
                edges.append({
                    'source_ref': ws_ref,
                    'target_ref': service_ref,
                    'relation': 'hosted_by',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
            continue

        if kind == 'browser-javascript-resource':
            url = str(item.get('url') or '')[:2048]
            if not url:
                continue
            js_ref = _graph_ref('browser-js', url)
            nodes.append({
                'plane': 'application',
                'kind': 'resource',
                'external_ref': js_ref,
                'label': url[:300],
                'protocol': 'https' if url.startswith('https://') else 'http',
                'properties': {
                    'resource_type': 'javascript',
                    'url': url,
                    'source_map_url': str(item.get('source_map_url') or '')[:2048],
                },
                'provenance': provenance,
            })
            service_ref = ensure_external_service(url)
            if service_ref:
                edges.append({
                    'source_ref': js_ref,
                    'target_ref': service_ref,
                    'relation': 'hosted_by',
                    'properties': {},
                    'evidence_refs': evidence_refs,
                    'provenance': provenance,
                })
            continue

    for page_ref in page_refs[:500]:
        for endpoint_ref in list(endpoint_ref_by_key.values())[:1000]:
            edges.append({
                'source_ref': page_ref,
                'target_ref': endpoint_ref,
                'relation': 'runtime_calls',
                'properties': {},
                'evidence_refs': evidence_refs,
                'provenance': provenance,
            })

    # Deduplicate by the graph's natural keys before hitting persistence.
    deduped_nodes: dict[str, dict[str, Any]] = {}
    for node in nodes:
        deduped_nodes[str(node['external_ref'])] = node
    deduped_edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in edges:
        key = (
            str(edge['source_ref']),
            str(edge['target_ref']),
            str(edge['relation']),
        )
        deduped_edges[key] = edge

    return upsert_graph_snapshot(
        project,
        list(deduped_nodes.values())[:10000],
        list(deduped_edges.values())[:25000],
    )
