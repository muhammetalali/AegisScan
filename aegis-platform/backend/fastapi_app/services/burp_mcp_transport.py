"""Bounded MCP SSE lifecycle for an approved Burp endpoint, without retries."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx

PROTOCOL_VERSION = '2024-11-05'
MAX_EVENT_BYTES = 1_048_576
MAX_TOTAL_BYTES = 4_194_304
MAX_EVENTS = 128
MAX_TOOL_PAGES = 8


class MCPTransportError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(f'Burp MCP transport rejected: {code}.')


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _origin(value: str) -> tuple[str, str, int]:
    try:
        p = urlsplit(value)
        if (p.scheme not in {'https', 'http'} or not p.hostname or p.username or p.password
                or p.fragment or any(ord(c) < 33 for c in value)):
            raise ValueError
        if p.scheme == 'http' and p.hostname not in {'localhost', '127.0.0.1', '::1'}:
            raise ValueError
        return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)
    except (ValueError, TypeError) as exc:
        raise MCPTransportError('invalid_endpoint') from exc


def message_endpoint(base: str, advertised: str) -> str:
    """Never forward authorization/session traffic to a different origin."""
    value = urljoin(base, advertised)
    if _origin(value) != _origin(base):
        raise MCPTransportError('endpoint_origin_mismatch')
    parsed = urlsplit(value)
    if not parsed.path:
        parsed = parsed._replace(path='/')
        value = parsed.geturl()
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (not parsed.path.startswith('/') or len(value) > 2048 or '\\' in value
            or set(query) - {'sessionId'} or any(len(v) != 1 or not v[0] for v in query.values())):
        raise MCPTransportError('invalid_message_endpoint')
    return value


@dataclass(frozen=True)
class MCPCallResult:
    result: dict[str, Any]
    request_id: str
    metadata: dict[str, Any]


async def _events(response: httpx.Response):
    buffer = b''
    total = event_bytes = events = 0
    kind, data = 'message', []
    async for chunk in response.aiter_raw():
        total += len(chunk)
        if total > MAX_TOTAL_BYTES:
            raise MCPTransportError('stream_size_limit')
        buffer += chunk
        while b'\n' in buffer:
            line, buffer = buffer.split(b'\n', 1)
            line = line.rstrip(b'\r')
            event_bytes += len(line) + 1
            if event_bytes > MAX_EVENT_BYTES:
                raise MCPTransportError('event_size_limit')
            try:
                decoded = line.decode('utf-8', errors='strict')
            except UnicodeDecodeError as exc:
                raise MCPTransportError('invalid_event_encoding') from exc
            if not decoded:
                if data:
                    events += 1
                    if events > MAX_EVENTS:
                        raise MCPTransportError('event_count_limit')
                    yield kind, '\n'.join(data)
                kind, data, event_bytes = 'message', [], 0
            elif not decoded.startswith(':'):
                key, _, value = decoded.partition(':')
                value = value[1:] if value.startswith(' ') else value
                if key == 'event':
                    kind = value
                elif key == 'data':
                    data.append(value)
        if len(buffer) + event_bytes > MAX_EVENT_BYTES:
            raise MCPTransportError('event_size_limit')
    raise MCPTransportError('stream_closed')


def _rpc_response(body: Any, request_id: str) -> dict[str, Any]:
    if (not isinstance(body, dict) or body.get('jsonrpc') != '2.0'
            or body.get('id') != request_id):
        raise MCPTransportError('mismatched_response')
    if 'error' in body or not isinstance(body.get('result'), dict):
        raise MCPTransportError('rpc_error')
    return body['result']


def _http1_schema(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get('inputSchema')
    expected = {'content': 'string', 'targetHostname': 'string', 'targetPort': 'integer', 'usesHttps': 'boolean'}
    if (not isinstance(schema, dict) or schema.get('type') != 'object'
            or set(schema) - {'type', 'properties', 'required', 'additionalProperties', 'title', 'description', '$schema'}
            or not isinstance(schema.get('required'), list)
            or len(schema['required']) != len(expected)
            or any(not isinstance(key, str) for key in schema['required'])
            or set(schema['required']) != set(expected)
            or not isinstance(schema.get('properties'), dict)
            or set(schema['properties']) != set(expected)
            or any(not isinstance(schema['properties'][key], dict)
                   or set(schema['properties'][key]) - {'type', 'description', 'title'}
                   or schema['properties'][key].get('type') != kind for key, kind in expected.items())):
        raise MCPTransportError('tool_schema_mismatch')
    return schema


async def _call(*, endpoint: str, provider_tool_name: str, arguments: dict[str, Any],
                request_id: str, bearer_token: str, deadline_seconds: float,
                expected_schema_sha256: str = '') -> MCPCallResult:
    _origin(endpoint)
    if urlsplit(endpoint).query:
        raise MCPTransportError('invalid_endpoint')
    headers = {'Accept': 'text/event-stream', 'Cache-Control': 'no-cache', 'Accept-Encoding': 'identity'}
    if bearer_token:
        headers['Authorization'] = f'Bearer {bearer_token}'
    timeout = httpx.Timeout(min(10.0, deadline_seconds), connect=min(5.0, deadline_seconds))
    async with asyncio.timeout(deadline_seconds):
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
            async with client.stream('GET', endpoint, headers=headers) as response:
                if (response.status_code != 200
                        or response.headers.get('content-type', '').split(';')[0] != 'text/event-stream'
                        or response.headers.get('content-encoding', 'identity') != 'identity'):
                    raise MCPTransportError('invalid_sse_response')
                events = _events(response)
                kind, advertised = await anext(events)
                if kind != 'endpoint':
                    raise MCPTransportError('missing_message_endpoint')
                post_url = message_endpoint(endpoint, advertised)
                queue: asyncio.Queue = asyncio.Queue(maxsize=32)

                async def read_stream():
                    try:
                        async for kind, data in events:
                            if kind != 'message':
                                raise MCPTransportError('unexpected_event')
                            try:
                                body = json.loads(data)
                            except (ValueError, TypeError) as exc:
                                raise MCPTransportError('invalid_rpc_json') from exc
                            if queue.full():
                                raise MCPTransportError('event_queue_limit')
                            queue.put_nowait(body)
                    except Exception as exc:
                        await queue.put(exc)

                reader = asyncio.create_task(read_stream())

                async def post(method: str, params: dict, rpc_id: str | None):
                    payload = {'jsonrpc': '2.0', 'method': method, 'params': params}
                    if rpc_id is not None:
                        payload['id'] = rpc_id
                    async with client.stream('POST', post_url, json=payload,
                                             headers={**headers, 'Accept': 'application/json'}) as reply:
                        if reply.status_code != 202:
                            raise MCPTransportError('message_post_rejected')
                        size = 0
                        async for chunk in reply.aiter_raw(chunk_size=8192):
                            size += len(chunk)
                            if size > 16_384:
                                raise MCPTransportError('post_size_limit')
                    if rpc_id is None:
                        return None
                    for _ in range(16):
                        item = await queue.get()
                        if isinstance(item, Exception):
                            raise item
                        if isinstance(item, dict) and 'id' not in item and item.get('method') == 'notifications/progress':
                            continue
                        return _rpc_response(item, rpc_id)
                    raise MCPTransportError('notification_limit')

                try:
                    initialized = await post('initialize', {
                        'protocolVersion': PROTOCOL_VERSION, 'capabilities': {},
                        'clientInfo': {'name': 'AegisScan Burp Gateway', 'version': '2.0'},
                    }, request_id + ':initialize')
                    if (initialized.get('protocolVersion') != PROTOCOL_VERSION
                            or not isinstance(initialized.get('serverInfo'), dict)
                            or not isinstance(initialized.get('capabilities'), dict)
                            or not isinstance(initialized['capabilities'].get('tools'), dict)):
                        raise MCPTransportError('initialization_mismatch')
                    await post('notifications/initialized', {}, None)
                    tools, cursor, seen = {}, None, set()
                    for page in range(MAX_TOOL_PAGES):
                        listing = await post('tools/list', {'cursor': cursor} if cursor else {}, request_id + f':tools:{page}')
                        if not isinstance(listing.get('tools'), list) or len(listing['tools']) > 64:
                            raise MCPTransportError('invalid_tools_list')
                        for tool in listing['tools']:
                            if (not isinstance(tool, dict) or not isinstance(tool.get('name'), str)
                                    or tool['name'] in tools or len(tool['name']) > 180):
                                raise MCPTransportError('invalid_tools_list')
                            tools[tool['name']] = tool
                        if len(tools) > 64:
                            raise MCPTransportError('tool_count_limit')
                        cursor = listing.get('nextCursor')
                        if not cursor:
                            break
                        if not isinstance(cursor, str) or len(cursor) > 512 or cursor in seen:
                            raise MCPTransportError('invalid_tools_cursor')
                        seen.add(cursor)
                    else:
                        raise MCPTransportError('tool_page_limit')
                    if provider_tool_name not in tools:
                        raise MCPTransportError('tool_not_advertised')
                    schema = _http1_schema(tools[provider_tool_name])
                    schema_sha = _sha(schema)
                    if expected_schema_sha256 and schema_sha != expected_schema_sha256:
                        raise MCPTransportError('tool_schema_pin_mismatch')
                    result = await post('tools/call', {'name': provider_tool_name, 'arguments': arguments}, request_id)
                    if result.get('isError') is True:
                        raise MCPTransportError('tool_execution_error')
                    return MCPCallResult(result=result, request_id=request_id, metadata={
                        'transport': 'sse', 'protocol_version': PROTOCOL_VERSION,
                        'server_info_sha256': _sha(initialized['serverInfo']),
                        'server_name': 'burp-suite' if initialized['serverInfo'].get('name') == 'burp-suite' else 'unrecognized',
                        'server_reported_version': initialized['serverInfo']['version']
                        if isinstance(initialized['serverInfo'].get('version'), str)
                        and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', initialized['serverInfo']['version'])
                        else 'not_reported',
                        'tools_sha256': _sha(tools), 'tool_schema_sha256': schema_sha,
                        'edition': 'not_reported', 'retry_count': 0,
                    })
                finally:
                    reader.cancel()
                    await asyncio.gather(reader, return_exceptions=True)


def call_burp_sse(*, endpoint: str, provider_tool_name: str, arguments: dict[str, Any],
                  request_id: str, bearer_token: str = '', deadline_seconds: float = 15.0,
                  expected_schema_sha256: str = '') -> MCPCallResult:
    if provider_tool_name != 'send_http1_request':
        raise MCPTransportError('unsupported_tool_binding')
    if (not isinstance(request_id, str) or not request_id or len(request_id) > 128
            or not 0 < deadline_seconds <= 30):
        raise MCPTransportError('invalid_call_limits')
    try:
        return asyncio.run(_call(endpoint=endpoint, provider_tool_name=provider_tool_name,
                                 arguments=arguments, request_id=request_id, bearer_token=bearer_token,
                                 deadline_seconds=deadline_seconds, expected_schema_sha256=expected_schema_sha256))
    except MCPTransportError:
        raise
    except (httpx.HTTPError, TimeoutError, ValueError, TypeError) as exc:
        raise MCPTransportError('transport_failed') from exc
