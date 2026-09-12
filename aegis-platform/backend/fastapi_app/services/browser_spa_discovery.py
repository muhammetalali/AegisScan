#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Awaitable, Callable
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit
from urllib.request import urlopen

import websockets

from fastapi_app.services.scanner_adapters import validate_authorized_web_target
from fastapi_app.services.scope_authorization import require_authorized_target

_SCHEMA = 'aegis.browser-spa-discovery.v1'
_MAX_SESSION_BYTES = 65536
_MAX_STORAGE_ENTRIES = 64
_MAX_COOKIES = 64
_HEADER_NAME_RE = re.compile(r'^[A-Za-z0-9!#$%&*+.^_|~-]{1,100}$')
_BLOCKED_SESSION_HEADERS = {
    'host', 'cookie', 'content-length', 'connection', 'transfer-encoding',
    'proxy-authorization', 'proxy-authenticate', 'upgrade',
}
_GRAPHQL_OPERATION_RE = re.compile(
    r'\b(query|mutation|subscription)\b(?:\s+([_A-Za-z][_0-9A-Za-z]*))?',
    re.IGNORECASE,
)
_SAFE_RESPONSE_HEADERS = {
    'access-control-allow-origin',
    'access-control-allow-credentials',
    'content-security-policy',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'permissions-policy',
    'referrer-policy',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'sourcemap',
    'x-sourcemap',
}


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    raw_scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if raw_scheme not in {'http', 'https', 'ws', 'wss'} or not host:
        raise ValueError('Browser target origin must be HTTP(S) or WebSocket')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Browser target contains an invalid port') from exc
    scheme = {'ws': 'http', 'wss': 'https'}.get(raw_scheme, raw_scheme)
    default = 80 if scheme == 'http' else 443
    authority = host if port in {None, default} else f'{host}:{port}'
    return urlunsplit((scheme, authority, '', '', ''))


def _same_origin(value: str, expected_origin: str) -> bool:
    try:
        return _origin(value) == expected_origin
    except ValueError:
        return False


def _canonical_url(value: str, *, base: str | None = None) -> str:
    raw = urljoin(base, value) if base else value
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return ''
    scheme = parsed.scheme.lower()
    if scheme not in {'http', 'https', 'ws', 'wss'}:
        return ''
    host = (parsed.hostname or '').lower().rstrip('.')
    if not host or parsed.username is not None or parsed.password is not None:
        return ''
    try:
        port = parsed.port
    except ValueError:
        return ''
    default = 80 if scheme in {'http', 'ws'} else 443
    authority = host if port in {None, default} else f'{host}:{port}'
    path = parsed.path or '/'
    query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})
    query = '&'.join(f'{quote(name, safe="[]_.-")}=*' for name in query_names[:64])
    return urlunsplit((scheme, authority, path[:2048], query, ''))


def _safe_identity_ref(value: str) -> str:
    candidate = str(value or 'anonymous').strip()
    if not candidate or len(candidate) > 255 or any(ch in candidate for ch in '\r\n\x00'):
        raise ValueError('identity_ref is invalid')
    return candidate


def _bounded_string_map(value: Any, *, limit: int, value_limit: int) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for raw_name, raw_value in list(value.items())[:limit]:
        name = str(raw_name)
        item = str(raw_value)
        if not name or len(name) > 200 or any(ch in name for ch in '\r\n\x00'):
            raise ValueError('Browser session key is invalid')
        if len(item.encode('utf-8')) > value_limit or '\x00' in item:
            raise ValueError('Browser session value exceeds safe bounds')
        result[name] = item
    return result


def _load_session(path: str | None) -> dict[str, Any]:
    if not path:
        return {'headers': {}, 'cookies': [], 'local_storage': {}, 'session_storage': {}}
    session_path = Path(path)
    if not session_path.is_file() or session_path.stat().st_size > _MAX_SESSION_BYTES:
        raise ValueError('Browser session file is missing or exceeds 64 KiB')
    try:
        payload = json.loads(session_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Browser session file must contain valid UTF-8 JSON') from exc
    if not isinstance(payload, dict):
        raise ValueError('Browser session payload must be a JSON object')
    unknown = set(payload) - {'headers', 'cookies', 'local_storage', 'session_storage'}
    if unknown:
        raise ValueError(f'Unsupported browser session fields: {sorted(unknown)}')

    headers = _bounded_string_map(payload.get('headers'), limit=32, value_limit=8192)
    normalized_headers: dict[str, str] = {}
    for name, value in headers.items():
        if not _HEADER_NAME_RE.fullmatch(name) or name.lower() in _BLOCKED_SESSION_HEADERS:
            raise ValueError(f'Browser session header is not allowed: {name}')
        if any(ch in value for ch in '\r\n'):
            raise ValueError('Browser session header value contains a control character')
        normalized_headers[name] = value

    raw_cookies = payload.get('cookies')
    cookies: list[dict[str, Any]] = []
    if raw_cookies is not None:
        if not isinstance(raw_cookies, list) or len(raw_cookies) > _MAX_COOKIES:
            raise ValueError('Browser session cookies must be a bounded list')
        for raw in raw_cookies:
            if not isinstance(raw, dict):
                raise ValueError('Browser session cookie entries must be objects')
            unknown_cookie = set(raw) - {'name', 'value', 'path', 'secure', 'httpOnly', 'sameSite'}
            if unknown_cookie:
                raise ValueError(f'Unsupported browser cookie fields: {sorted(unknown_cookie)}')
            name = str(raw.get('name') or '').strip()
            cookie_value = str(raw.get('value') or '')
            path_value = str(raw.get('path') or '/')
            if not name or len(name) > 256 or any(ch in name for ch in '\r\n\x00;'):
                raise ValueError('Browser cookie name is invalid')
            if len(cookie_value.encode('utf-8')) > 8192 or any(ch in cookie_value for ch in '\r\n\x00'):
                raise ValueError('Browser cookie value exceeds safe bounds')
            if not path_value.startswith('/') or len(path_value) > 1024:
                raise ValueError('Browser cookie path is invalid')
            same_site = str(raw.get('sameSite') or '').strip().capitalize()
            if same_site and same_site not in {'Strict', 'Lax', 'None'}:
                raise ValueError('Browser cookie sameSite must be Strict, Lax, or None')
            cookie = {
                'name': name,
                'value': cookie_value,
                'path': path_value,
                'secure': bool(raw.get('secure', False)),
                'httpOnly': bool(raw.get('httpOnly', False)),
            }
            if same_site:
                cookie['sameSite'] = same_site
            cookies.append(cookie)

    return {
        'headers': normalized_headers,
        'cookies': cookies,
        'local_storage': _bounded_string_map(
            payload.get('local_storage'), limit=_MAX_STORAGE_ENTRIES, value_limit=8192
        ),
        'session_storage': _bounded_string_map(
            payload.get('session_storage'), limit=_MAX_STORAGE_ENTRIES, value_limit=8192
        ),
    }


def _graphql_metadata(post_data: Any) -> dict[str, Any] | None:
    if not isinstance(post_data, str) or not post_data or len(post_data) > 262144:
        return None
    try:
        payload = json.loads(post_data)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    query = payload.get('query')
    if not isinstance(query, str) or not query.strip():
        return None
    match = _GRAPHQL_OPERATION_RE.search(query)
    operation_type = match.group(1).lower() if match else 'query'
    operation_name = str(
        payload.get('operationName') or (match.group(2) if match else '') or 'anonymous'
    )[:200]
    variables = payload.get('variables')
    variable_keys = sorted(str(key)[:200] for key in variables)[:100] if isinstance(variables, dict) else []
    return {
        'operation_type': operation_type,
        'operation_name': operation_name,
        'variable_keys': variable_keys,
    }


def _safe_response_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    return {
        name: lowered[name][:2048]
        for name in sorted(_SAFE_RESPONSE_HEADERS)
        if name in lowered
    }


class _CDP:
    def __init__(
        self,
        websocket_url: str,
        event_handler: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        self.websocket_url = websocket_url
        self.event_handler = event_handler
        self.websocket: Any = None
        self._reader: asyncio.Task[Any] | None = None
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._events: set[asyncio.Task[Any]] = set()
        self._next_id = 1

    async def __aenter__(self) -> '_CDP':
        self.websocket = await websockets.connect(
            self.websocket_url,
            open_timeout=10,
            close_timeout=2,
            max_size=8 * 1024 * 1024,
        )
        self._reader = asyncio.create_task(self._read_loop())
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        if self._events:
            await asyncio.gather(*tuple(self._events), return_exceptions=True)
        if self.websocket is not None:
            await self.websocket.close()
        if self._reader is not None:
            self._reader.cancel()
            await asyncio.gather(self._reader, return_exceptions=True)
        return False

    async def _read_loop(self) -> None:
        assert self.websocket is not None
        async for raw in self.websocket:
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if 'id' in message:
                future = self._pending.pop(int(message['id']), None)
                if future is None or future.done():
                    continue
                if 'error' in message:
                    future.set_exception(RuntimeError(str(message['error'])[:2000]))
                else:
                    future.set_result(message.get('result') or {})
                continue
            task = asyncio.create_task(self.event_handler(message))
            self._events.add(task)
            task.add_done_callback(self._events.discard)

    async def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        assert self.websocket is not None
        message_id = self._next_id
        self._next_id += 1
        future = asyncio.get_running_loop().create_future()
        self._pending[message_id] = future
        await self.websocket.send(json.dumps({'id': message_id, 'method': method, 'params': params or {}}))
        try:
            result = await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(message_id, None)
        return result if isinstance(result, dict) else {}


def _chromium_binary() -> str:
    for name in ('chromium', 'chromium-browser'):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError('Chromium is not installed on the scanner worker')


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=5)


def _devtools_page(profile: Path, process: subprocess.Popen[bytes]) -> str:
    active = profile / 'DevToolsActivePort'
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Chromium exited before DevTools became available')
        if active.is_file():
            lines = active.read_text(encoding='utf-8', errors='replace').splitlines()
            if lines and lines[0].isdigit():
                port = int(lines[0])
                with urlopen(f'http://127.0.0.1:{port}/json/list', timeout=2) as response:
                    targets = json.loads(response.read().decode('utf-8'))
                for target in targets if isinstance(targets, list) else []:
                    if (
                        isinstance(target, dict)
                        and target.get('type') == 'page'
                        and target.get('webSocketDebuggerUrl')
                    ):
                        return str(target['webSocketDebuggerUrl'])
        time.sleep(0.05)
    raise RuntimeError('Chromium DevTools endpoint did not become ready')


_INSTRUMENTATION_SCRIPT = r"""
(() => {
  const state = {
    postMessageListeners: 0,
    postMessagesSent: 0,
    innerHTMLWrites: 0,
    insertAdjacentHTMLCalls: 0,
    documentWriteCalls: 0,
    objectPrototypeBaseline: Object.getOwnPropertyNames(Object.prototype),
    blockedWebSocketCount: 0,
    blockedWebTransportCount: 0
  };
  Object.defineProperty(globalThis, '__aegisRuntimeSignals', {value: state, configurable: false});
  try {
    const targetOrigin = __AEGIS_TARGET_ORIGIN__;
    const NativeWebSocket = window.WebSocket;
    const websocketProxy = new Proxy(NativeWebSocket, {
      construct(Target, args) {
        const raw = String(args[0] || '');
        const parsed = new URL(raw, location.href);
        const comparable = (parsed.protocol === 'ws:' ? 'http:' : parsed.protocol === 'wss:' ? 'https:' : parsed.protocol) + '//' + parsed.host;
        if (comparable !== targetOrigin) {
          state.blockedWebSocketCount += 1;
          throw new DOMException('Cross-origin WebSocket blocked by AegisScan browser isolation', 'SecurityError');
        }
        return Reflect.construct(Target, args, Target);
      }
    });
    Object.defineProperty(websocketProxy, 'CONNECTING', {value: NativeWebSocket.CONNECTING});
    Object.defineProperty(websocketProxy, 'OPEN', {value: NativeWebSocket.OPEN});
    Object.defineProperty(websocketProxy, 'CLOSING', {value: NativeWebSocket.CLOSING});
    Object.defineProperty(websocketProxy, 'CLOSED', {value: NativeWebSocket.CLOSED});
    window.WebSocket = websocketProxy;
  } catch (_) {}
  try {
    if (typeof window.WebTransport === 'function') {
      const NativeWebTransport = window.WebTransport;
      window.WebTransport = new Proxy(NativeWebTransport, {
        construct(Target, args) {
          const parsed = new URL(String(args[0] || ''), location.href);
          if (parsed.origin !== __AEGIS_TARGET_ORIGIN__) {
            state.blockedWebTransportCount += 1;
            throw new DOMException('Cross-origin WebTransport blocked by AegisScan browser isolation', 'SecurityError');
          }
          return Reflect.construct(Target, args, Target);
        }
      });
    }
  } catch (_) {}
  try {
    const originalAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, options) {
      if (type === 'message') state.postMessageListeners += 1;
      return originalAdd.call(this, type, listener, options);
    };
  } catch (_) {}
  try {
    const originalPost = window.postMessage.bind(window);
    window.postMessage = function(...args) {
      state.postMessagesSent += 1;
      return originalPost(...args);
    };
  } catch (_) {}
  try {
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (descriptor && descriptor.set && descriptor.get) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        get: descriptor.get,
        set(value) {
          state.innerHTMLWrites += 1;
          return descriptor.set.call(this, value);
        }
      });
    }
  } catch (_) {}
  try {
    const originalInsert = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(...args) {
      state.insertAdjacentHTMLCalls += 1;
      return originalInsert.apply(this, args);
    };
  } catch (_) {}
  try {
    const originalWrite = document.write.bind(document);
    document.write = function(...args) {
      state.documentWriteCalls += 1;
      return originalWrite(...args);
    };
  } catch (_) {}
})();
"""


def _instrumentation_script(target_origin: str) -> str:
    return _INSTRUMENTATION_SCRIPT.replace(
        '__AEGIS_TARGET_ORIGIN__',
        json.dumps(target_origin),
    )


def _storage_seed_script(target_origin: str, session: dict[str, Any]) -> str:
    local_json = json.dumps(session['local_storage'], ensure_ascii=False)
    session_json = json.dumps(session['session_storage'], ensure_ascii=False)
    origin_json = json.dumps(target_origin)
    return f"""
(() => {{
  if (location.origin !== {origin_json}) return;
  try {{
    const values = {local_json};
    for (const [key, value] of Object.entries(values)) localStorage.setItem(key, String(value));
  }} catch (_) {{}}
  try {{
    const values = {session_json};
    for (const [key, value] of Object.entries(values)) sessionStorage.setItem(key, String(value));
  }} catch (_) {{}}
}})();
"""


_RUNTIME_SUMMARY_EXPRESSION = r"""
(() => {
  const safeKeys = (storage) => {
    try { return Object.keys(storage).slice(0, 200); } catch (_) { return []; }
  };
  const canonicalElements = (selector, attr) => {
    const values = [];
    for (const node of Array.from(document.querySelectorAll(selector)).slice(0, 500)) {
      try {
        const value = node[attr] || node.getAttribute(attr) || '';
        if (value) values.push(String(value));
      } catch (_) {}
    }
    return Array.from(new Set(values)).slice(0, 500);
  };
  let clobberCount = 0;
  try {
    for (const node of Array.from(document.querySelectorAll('[id],[name]')).slice(0, 2000)) {
      const key = node.id || node.getAttribute('name');
      if (key && Object.prototype.hasOwnProperty.call(window, key)) clobberCount += 1;
    }
  } catch (_) {}
  const signals = globalThis.__aegisRuntimeSignals || {};
  const baseline = Array.isArray(signals.objectPrototypeBaseline) ? signals.objectPrototypeBaseline : [];
  const currentPrototype = Object.getOwnPropertyNames(Object.prototype);
  const prototypeAdditions = currentPrototype.filter((name) => !baseline.includes(name)).slice(0, 100);
  return {
    title: String(document.title || '').slice(0, 500),
    location: String(location.href || ''),
    links: canonicalElements('a[href]', 'href'),
    forms: canonicalElements('form[action]', 'action'),
    scripts: canonicalElements('script[src]', 'src'),
    localStorageKeys: safeKeys(localStorage),
    sessionStorageKeys: safeKeys(sessionStorage),
    domClobberingCount: clobberCount,
    prototypeAdditions,
    signals: {
      postMessageListeners: Number(signals.postMessageListeners || 0),
      postMessagesSent: Number(signals.postMessagesSent || 0),
      innerHTMLWrites: Number(signals.innerHTMLWrites || 0),
      insertAdjacentHTMLCalls: Number(signals.insertAdjacentHTMLCalls || 0),
      documentWriteCalls: Number(signals.documentWriteCalls || 0),
      blockedWebSocketCount: Number(signals.blockedWebSocketCount || 0),
      blockedWebTransportCount: Number(signals.blockedWebTransportCount || 0)
    }
  };
})()
"""


async def discover(
    target: str,
    *,
    identity_ref: str,
    session_file: str | None,
    wait_ms: int,
    max_events: int,
) -> dict[str, Any]:
    target = validate_authorized_web_target(target)
    require_authorized_target(target, url=True, resolve_dns=True)
    identity_ref = _safe_identity_ref(identity_ref)
    target_origin = _origin(target)
    session = _load_session(session_file)

    profile = Path(tempfile.mkdtemp(prefix='aegis-browser-profile-'))
    os.chmod(profile, 0o700)
    process: subprocess.Popen[bytes] | None = None
    events: list[dict[str, Any]] = []
    graphql: list[dict[str, Any]] = []
    web_sockets: list[str] = []
    redirects: list[str] = []
    request_meta: dict[str, dict[str, Any]] = {}
    truncated = False
    blocked_out_of_scope_requests = 0

    try:
        process = subprocess.Popen(
            [
                _chromium_binary(),
                '--headless=new',
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-background-networking',
                '--disable-component-update',
                '--disable-default-apps',
                '--disable-extensions',
                '--disable-sync',
                '--metrics-recording-only',
                '--no-first-run',
                '--no-default-browser-check',
                '--remote-debugging-address=127.0.0.1',
                '--remote-debugging-port=0',
                f'--user-data-dir={profile}',
                'about:blank',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        websocket_url = await asyncio.to_thread(_devtools_page, profile, process)

        cdp_ref: dict[str, _CDP] = {}

        async def on_event(message: dict[str, Any]) -> None:
            nonlocal truncated, blocked_out_of_scope_requests
            method = str(message.get('method') or '')
            params = message.get('params') if isinstance(message.get('params'), dict) else {}

            if method == 'Fetch.requestPaused':
                request = params.get('request') if isinstance(params.get('request'), dict) else {}
                raw_url = str(request.get('url') or '')
                request_id = params.get('requestId')
                parsed = urlsplit(raw_url)
                if parsed.scheme in {'http', 'https', 'ws', 'wss'}:
                    try:
                        require_authorized_target(_origin(raw_url), url=True, resolve_dns=True)
                    except ValueError:
                        blocked_out_of_scope_requests += 1
                        try:
                            await cdp_ref['client'].call(
                                'Fetch.failRequest',
                                {'requestId': request_id, 'errorReason': 'BlockedByClient'},
                                timeout=5,
                            )
                        except Exception:
                            pass
                        return
                payload: dict[str, Any] = {'requestId': request_id}
                if _same_origin(raw_url, target_origin) and session['headers']:
                    existing = request.get('headers') if isinstance(request.get('headers'), dict) else {}
                    merged = {str(k): str(v) for k, v in existing.items()}
                    existing_lower = {key.lower(): key for key in merged}
                    for name, header_value in session['headers'].items():
                        previous = existing_lower.get(name.lower())
                        if previous:
                            merged.pop(previous, None)
                        merged[name] = header_value
                    payload['headers'] = [
                        {'name': name, 'value': header_value}
                        for name, header_value in merged.items()
                        if len(name) <= 100 and len(header_value) <= 8192
                    ]
                try:
                    await cdp_ref['client'].call('Fetch.continueRequest', payload, timeout=5)
                except Exception:
                    pass
                return

            if method == 'Network.requestWillBeSent':
                request = params.get('request') if isinstance(params.get('request'), dict) else {}
                raw_url = str(request.get('url') or '')
                canonical = _canonical_url(raw_url)
                if not canonical:
                    return
                request_id = str(params.get('requestId') or '')
                resource_type = str(params.get('type') or '')[:80]
                http_method = str(request.get('method') or 'GET').upper()[:16]
                document_url = _canonical_url(str(params.get('documentURL') or ''))
                request_meta[request_id] = {
                    'url': canonical,
                    'method': http_method,
                    'resource_type': resource_type,
                    'document_url': document_url,
                }
                meta = _graphql_metadata(request.get('postData'))
                if meta is not None and len(graphql) < max_events:
                    graphql.append({
                        'endpoint': canonical,
                        'method': http_method,
                        'document_url': document_url,
                        **meta,
                    })
                if len(events) < max_events:
                    events.append({
                        'kind': 'request',
                        'url': canonical,
                        'method': http_method,
                        'resource_type': resource_type,
                        'document_url': document_url,
                    })
                else:
                    truncated = True
                return

            if method == 'Network.responseReceived':
                response = params.get('response') if isinstance(params.get('response'), dict) else {}
                canonical = _canonical_url(str(response.get('url') or ''))
                if not canonical:
                    return
                request_id = str(params.get('requestId') or '')
                base = request_meta.get(request_id, {})
                if len(events) < max_events:
                    events.append({
                        'kind': 'response',
                        'url': canonical,
                        'method': str(base.get('method') or '')[:16],
                        'resource_type': str(
                            params.get('type') or base.get('resource_type') or ''
                        )[:80],
                        'status': int(response.get('status') or 0),
                        'mime_type': str(response.get('mimeType') or '')[:200],
                        'headers': _safe_response_headers(response.get('headers')),
                    })
                else:
                    truncated = True
                return

            if method == 'Network.webSocketCreated':
                canonical = _canonical_url(str(params.get('url') or ''))
                if canonical and canonical not in web_sockets and len(web_sockets) < max_events:
                    web_sockets.append(canonical)
                return

            if method == 'Page.frameNavigated':
                frame = params.get('frame') if isinstance(params.get('frame'), dict) else {}
                if frame.get('parentId'):
                    return
                canonical = _canonical_url(str(frame.get('url') or ''))
                if canonical and (not redirects or redirects[-1] != canonical):
                    redirects.append(canonical)

        async with _CDP(websocket_url, on_event) as cdp:
            cdp_ref['client'] = cdp
            await cdp.call('Page.enable')
            await cdp.call('Runtime.enable')
            await cdp.call('Network.enable', {'maxTotalBufferSize': 8 * 1024 * 1024})
            await cdp.call(
                'Fetch.enable',
                {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]},
            )
            await cdp.call(
                'Page.addScriptToEvaluateOnNewDocument',
                {'source': _instrumentation_script(target_origin)},
            )
            await cdp.call(
                'Page.addScriptToEvaluateOnNewDocument',
                {'source': _storage_seed_script(target_origin, session)},
            )

            if session['cookies']:
                cookie_params = []
                for cookie in session['cookies']:
                    item = dict(cookie)
                    item['url'] = target_origin + '/'
                    cookie_params.append(item)
                await cdp.call('Network.setCookies', {'cookies': cookie_params})

            await cdp.call('Page.navigate', {'url': target}, timeout=10)
            await asyncio.sleep(wait_ms / 1000.0)

            runtime = await cdp.call(
                'Runtime.evaluate',
                {'expression': _RUNTIME_SUMMARY_EXPRESSION, 'returnByValue': True},
            )
            runtime_value = (
                runtime.get('result', {}).get('value')
                if isinstance(runtime.get('result'), dict)
                else None
            )
            runtime_summary = runtime_value if isinstance(runtime_value, dict) else {}

            try:
                cookie_result = await cdp.call('Network.getAllCookies')
                raw_cookies = (
                    cookie_result.get('cookies')
                    if isinstance(cookie_result.get('cookies'), list)
                    else []
                )
            except Exception:
                raw_cookies = []

            await asyncio.sleep(0.1)

        observations: list[dict[str, Any]] = []
        seen_routes: set[str] = set()
        for raw in [
            runtime_summary.get('location'),
            *(runtime_summary.get('links') or []),
            *(runtime_summary.get('forms') or []),
        ]:
            canonical = _canonical_url(str(raw or ''), base=target)
            if canonical and canonical not in seen_routes:
                seen_routes.add(canonical)
                observations.append({'kind': 'browser-page-route', 'url': canonical})

        responses: dict[tuple[str, str], dict[str, Any]] = {}
        for event in events:
            if event.get('kind') != 'response':
                continue
            key = (str(event.get('method') or ''), str(event.get('url') or ''))
            responses[key] = event

        seen_endpoints: set[tuple[str, str]] = set()
        for event in events:
            if event.get('kind') != 'request':
                continue
            resource_type = str(event.get('resource_type') or '')
            if resource_type not in {'XHR', 'Fetch', 'Document', 'Other'}:
                continue
            method = str(event.get('method') or 'GET')
            url = str(event.get('url') or '')
            key = (method, url)
            if key in seen_endpoints:
                continue
            seen_endpoints.add(key)
            response = responses.get(key, {})
            observations.append({
                'kind': 'browser-http-endpoint',
                'url': url,
                'method': method,
                'resource_type': resource_type,
                'document_url': str(event.get('document_url') or '')[:2048],
                'status': int(response.get('status') or 0),
                'mime_type': str(response.get('mime_type') or '')[:200],
                'response_headers': (
                    response.get('headers')
                    if isinstance(response.get('headers'), dict)
                    else {}
                ),
            })

        graphql_seen: set[tuple[str, str, str]] = set()
        for item in graphql:
            key = (
                str(item.get('endpoint') or ''),
                str(item.get('operation_type') or ''),
                str(item.get('operation_name') or ''),
            )
            if key in graphql_seen:
                continue
            graphql_seen.add(key)
            observations.append({'kind': 'browser-graphql-operation', **item})

        for url in sorted(set(web_sockets)):
            observations.append({'kind': 'browser-websocket-channel', 'url': url})

        script_urls = {
            _canonical_url(str(value or ''), base=target)
            for value in runtime_summary.get('scripts') or []
        }
        script_urls.discard('')
        for event in events:
            if event.get('kind') == 'response' and (
                str(event.get('resource_type') or '') == 'Script'
                or 'javascript' in str(event.get('mime_type') or '').lower()
            ):
                script_urls.add(str(event.get('url') or ''))
        for url in sorted(script_urls):
            response = next(
                (
                    item
                    for item in events
                    if item.get('kind') == 'response' and item.get('url') == url
                ),
                {},
            )
            headers = (
                response.get('headers')
                if isinstance(response.get('headers'), dict)
                else {}
            )
            map_header = str(headers.get('sourcemap') or headers.get('x-sourcemap') or '')
            source_map = _canonical_url(map_header, base=url) if map_header else ''
            observation: dict[str, Any] = {
                'kind': 'browser-javascript-resource',
                'url': url,
            }
            if source_map:
                observation['source_map_url'] = source_map
            observations.append(observation)

        target_host = (urlsplit(target).hostname or '').lower()
        cookie_metadata = []
        for cookie in raw_cookies[:_MAX_COOKIES]:
            if not isinstance(cookie, dict):
                continue
            domain = str(cookie.get('domain') or '')[:255]
            if domain.lstrip('.').lower() != target_host:
                continue
            cookie_metadata.append({
                'name': str(cookie.get('name') or '')[:256],
                'domain': domain,
                'path': str(cookie.get('path') or '/')[:1024],
                'secure': bool(cookie.get('secure')),
                'http_only': bool(cookie.get('httpOnly')),
                'same_site': str(cookie.get('sameSite') or '')[:20],
                'session': bool(cookie.get('session')),
            })

        signals = (
            runtime_summary.get('signals')
            if isinstance(runtime_summary.get('signals'), dict)
            else {}
        )
        observations.insert(0, {
            'kind': 'browser-spa-summary',
            'identity_ref': identity_ref,
            'target_origin': target_origin,
            'page_title': str(runtime_summary.get('title') or '')[:500],
            'local_storage_keys': sorted(
                str(x)[:200]
                for x in (runtime_summary.get('localStorageKeys') or [])[:200]
            ),
            'session_storage_keys': sorted(
                str(x)[:200]
                for x in (runtime_summary.get('sessionStorageKeys') or [])[:200]
            ),
            'cookies': cookie_metadata,
            'post_message_listener_count': int(signals.get('postMessageListeners') or 0),
            'post_message_send_count': int(signals.get('postMessagesSent') or 0),
            'inner_html_write_count': int(signals.get('innerHTMLWrites') or 0),
            'insert_adjacent_html_count': int(signals.get('insertAdjacentHTMLCalls') or 0),
            'document_write_count': int(signals.get('documentWriteCalls') or 0),
            'blocked_websocket_count': int(signals.get('blockedWebSocketCount') or 0),
            'blocked_webtransport_count': int(signals.get('blockedWebTransportCount') or 0),
            'dom_clobbering_count': int(runtime_summary.get('domClobberingCount') or 0),
            'prototype_additions': [
                str(value)[:200]
                for value in (runtime_summary.get('prototypeAdditions') or [])[:100]
            ],
            'redirect_chain': redirects[:100],
            'profile_isolation': 'dedicated-ephemeral-user-data-dir',
            'credential_transport': 'same-origin-request-interception',
            'event_truncated': truncated,
            'blocked_out_of_scope_request_count': blocked_out_of_scope_requests,
        })

        return {
            'schema': _SCHEMA,
            'target': _canonical_url(target),
            'identity_ref': identity_ref,
            'observation_count': min(len(observations), max_events + 1000),
            'observations': observations[: max_events + 1000],
        }
    finally:
        if process is not None:
            _terminate(process)
        shutil.rmtree(profile, ignore_errors=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='AegisScan stateful Browser/SPA discovery engine'
    )
    parser.add_argument('--session-file')
    parser.add_argument('target')
    parser.add_argument('--identity-ref', default='anonymous')
    parser.add_argument('--wait-ms', type=int, default=4000)
    parser.add_argument('--max-events', type=int, default=2000)
    args = parser.parse_args()
    if not 1000 <= args.wait_ms <= 15000:
        parser.error('--wait-ms must be between 1000 and 15000')
    if not 100 <= args.max_events <= 5000:
        parser.error('--max-events must be between 100 and 5000')
    return args


def main() -> int:
    args = _parse_args()
    try:
        result = asyncio.run(
            discover(
                args.target,
                identity_ref=args.identity_ref,
                session_file=args.session_file,
                wait_ms=args.wait_ms,
                max_events=args.max_events,
            )
        )
    except Exception as exc:
        print(json.dumps({'schema': _SCHEMA, 'error': str(exc)[:2000]}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
