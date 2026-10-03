from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fastapi_app.services.burp_mcp_transport import (
    MCPTransportError, call_burp_sse, message_endpoint, PROTOCOL_VERSION,
)
from fastapi_app.services.burp_http_probe import health_request_arguments, summarize_health_result


def http1_tool():
    return {'name': 'send_http1_request', 'description': 'Contract fixture, not Burp.', 'inputSchema': {
        'type': 'object', 'properties': {k: {'type': v} for k, v in {
            'content': 'string', 'targetHostname': 'string', 'targetPort': 'integer', 'usesHttps': 'boolean',
        }.items()}, 'required': ['content', 'targetHostname', 'targetPort', 'usesHttps'],
    }}


class SSEContractServer:
    """Local test double for lifecycle/security tests; never a live Burp claim."""
    def __init__(self, mode='valid'):
        self.mode = mode
        self.messages = []
        self.events = queue.Queue()
        self.closed = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Connection', 'close')
                self.end_headers()
                announced = '/message?sessionId=test-session'
                if outer.mode == 'foreign_endpoint':
                    announced = 'http://127.0.0.1:1/message?sessionId=test-session'
                self.wfile.write(f'event: endpoint\r\ndata: {announced}\r\n\r\n'.encode())
                self.wfile.flush()
                try:
                    while not outer.closed.is_set():
                        try:
                            item = outer.events.get(timeout=0.1)
                        except queue.Empty:
                            continue
                        if item is None:
                            break
                        encoded = item if isinstance(item, bytes) else (
                            'event: message\ndata: ' + json.dumps(item, ensure_ascii=False) + '\n\n').encode()
                        # Exercise partial UTF-8, CRLF and small network chunks.
                        chunk_size = 7 if len(encoded) < 8192 else 4096
                        for i in range(0, len(encoded), chunk_size):
                            self.wfile.write(encoded[i:i+chunk_size])
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_POST(self):
                count = int(self.headers['Content-Length'])
                body = json.loads(self.rfile.read(count))
                outer.messages.append(body)
                self.send_response(202)
                self.send_header('Content-Length', '0')
                self.end_headers()
                rpc_id, method = body.get('id'), body['method']
                if method == 'initialize':
                    result = {'protocolVersion': PROTOCOL_VERSION, 'capabilities': {'tools': {}},
                              'serverInfo': {'name': 'Arabic عقد fixture', 'version': 'test-only'}}
                    if outer.mode == 'wrong_protocol':
                        result['protocolVersion'] = 'unsupported'
                elif method == 'notifications/initialized':
                    return
                elif method == 'tools/list':
                    tool = http1_tool()
                    if outer.mode == 'wrong_schema':
                        tool['inputSchema']['properties']['targetPort']['type'] = 'string'
                    if outer.mode == 'extra_constraint':
                        tool['inputSchema']['properties']['targetPort']['minimum'] = 65535
                    if outer.mode == 'missing_tool':
                        tool['name'] = 'different_tool'
                    result = {'tools': [tool]}
                    if outer.mode == 'duplicate_tool':
                        result['tools'].append(tool)
                    if outer.mode == 'cursor_loop':
                        result = {'tools': [], 'nextCursor': 'same-cursor'}
                elif method == 'tools/call':
                    if outer.mode == 'timeout':
                        return
                    raw = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: synthetic-private-value\r\n\r\n'
                    raw += json.dumps({'status': 'ok', 'fixture': 'bac-target', 'extra': 'synthetic-body-private'})
                    result = {'content': [{'type': 'text', 'text': raw}], 'isError': outer.mode == 'tool_error'}
                else:
                    raise AssertionError(method)
                response = {'jsonrpc': '2.0', 'id': rpc_id, 'result': result}
                if outer.mode == 'wrong_id':
                    response['id'] = 'other-request'
                if outer.mode == 'rpc_error':
                    response.pop('result')
                    response['error'] = {'code': -1, 'message': 'synthetic-sensitive-error'}
                outer.events.put(response)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.endpoint = f'http://127.0.0.1:{self.server.server_port}/sse'

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.closed.set()
        self.events.put(None)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def call(server, **options):
    return call_burp_sse(endpoint=server.endpoint, provider_tool_name='send_http1_request',
                         arguments=health_request_arguments('http://127.0.0.1:18081'),
                         request_id='transport-test', **options)


def test_sse_initialize_discover_call_and_redacted_health_summary():
    with SSEContractServer() as server:
        result = call(server)
        assert [x['method'] for x in server.messages] == [
            'initialize', 'notifications/initialized', 'tools/list', 'tools/call',
        ]
        assert server.messages[-1]['params']['arguments']['content'].startswith('GET /health HTTP/1.1\r\n')
    summary = summarize_health_result({'mcp_result': result.result, 'transport_metadata': result.metadata})
    assert summary['transport_probe_passed'] is True
    assert summary['lab_solved'] is False
    assert summary['live_fixture_revision_verified'] is False
    assert 'synthetic-private-value' not in json.dumps(summary)
    assert 'synthetic-body-private' not in json.dumps(summary)
    assert result.metadata['retry_count'] == 0
    assert result.metadata['edition'] == 'not_reported'


@pytest.mark.parametrize('mode,code', [
    ('foreign_endpoint', 'endpoint_origin_mismatch'), ('wrong_protocol', 'initialization_mismatch'),
    ('wrong_schema', 'tool_schema_mismatch'), ('extra_constraint', 'tool_schema_mismatch'),
    ('missing_tool', 'tool_not_advertised'), ('duplicate_tool', 'invalid_tools_list'),
    ('cursor_loop', 'invalid_tools_cursor'), ('wrong_id', 'mismatched_response'), ('rpc_error', 'rpc_error'),
])
def test_invalid_connection_or_discovery_never_calls_tool(mode, code):
    with SSEContractServer(mode) as server:
        with pytest.raises(MCPTransportError) as error:
            call(server)
        assert error.value.code == code
        assert not any(m['method'] == 'tools/call' for m in server.messages)
        assert 'synthetic-sensitive-error' not in str(error.value)


def test_tool_error_and_timeout_are_not_retried_or_reported_success():
    for mode in ['tool_error', 'timeout']:
        with SSEContractServer(mode) as server:
            with pytest.raises(MCPTransportError):
                call(server, deadline_seconds=1)
            assert len([m for m in server.messages if m['method'] == 'tools/call']) == 1


def test_schema_pin_must_match_discovered_schema():
    with SSEContractServer() as server:
        with pytest.raises(MCPTransportError, match='tool_schema_pin_mismatch'):
            call(server, expected_schema_sha256='0' * 64)
        assert not any(m['method'] == 'tools/call' for m in server.messages)


@pytest.mark.parametrize('advertised', ['https://other.invalid/message', '//other.invalid/message',
                                     '/message?token=private', '/message?sessionId=a&sessionId=b',
                                     '/message#fragment', '/message?sessionId='])
def test_message_endpoint_cannot_escape_origin_or_admit_arbitrary_query(advertised):
    with pytest.raises(MCPTransportError):
        message_endpoint('https://burp.invalid/sse', advertised)


@pytest.mark.parametrize('target', ['https://u:p@fixture.invalid', 'http://fixture.invalid/path',
                                  'http://fixture.invalid/?next=other', 'file:///etc/passwd',
                                  'http://fixture.invalid\r\nX-Injection: yes'])
def test_server_built_request_cannot_accept_client_raw_content_or_invalid_origin(target):
    with pytest.raises(ValueError):
        health_request_arguments(target)


@pytest.mark.parametrize('raw', ['Send HTTP request denied by Burp Suite', '<no response>',
                               'HTTP/1.1 302 Found\r\nLocation: https://other.invalid\r\n\r\n',
                               'HTTP/1.1 200 OK\r\n\r\n{"fixture":"unrelated","status":"ok"}'])
def test_denial_empty_redirect_and_unrelated_target_do_not_pass_probe(raw):
    payload = {'mcp_result': {'content': [{'type': 'text', 'text': raw}]}, 'transport_metadata': {}}
    try:
        summary = summarize_health_result(payload)
    except ValueError:
        return
    assert summary['transport_probe_passed'] is False


def test_sse_event_size_limit_is_enforced():
    with SSEContractServer('timeout') as server:
        server.events.put(b'event: message\ndata: ' + b'x' * 1_048_577 + b'\n\n')
        with pytest.raises(MCPTransportError, match='event_size_limit'):
            call(server)
