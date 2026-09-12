from __future__ import annotations

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response

app = FastAPI(title='AegisScan Browser SPA Fixture')
AUTHORIZATION = 'Bearer browser-fixture-token'


@app.get('/health')
async def health():
    return {'status': 'ok'}


@app.get('/')
async def index():
    html = '''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Aegis Browser SPA Fixture</title>
</head>
<body>
  <nav><a href="/dashboard">Dashboard</a></nav>
  <form action="/api/profile" method="get"><input name="q"></form>
  <div id="sink"></div>
  <div id="location"></div>
  <script src="/static/app.js"></script>
</body>
</html>'''
    response = HTMLResponse(html)
    response.headers['Content-Security-Policy'] = "default-src 'self' http://127.0.0.1:18084 ws://127.0.0.1:18083; connect-src 'self' http://127.0.0.1:18084 http://192.0.2.1 ws://127.0.0.1:18083"
    response.set_cookie(
        'server_session',
        'server-cookie-secret-must-not-persist',
        httponly=True,
        secure=False,
        samesite='lax',
    )
    return response


@app.get('/dashboard')
async def dashboard():
    return HTMLResponse('<!doctype html><title>Dashboard</title><a href="/">Home</a>')


@app.get('/api/profile')
async def profile(request: Request):
    if request.headers.get('authorization') != AUTHORIZATION:
        return JSONResponse({'error': 'unauthorized'}, status_code=401)
    return {
        'user': 'alice',
        'tenant': 'tenant-a',
        'server_secret': 'response-secret-must-not-persist',
    }


@app.post('/graphql')
async def graphql(request: Request):
    if request.headers.get('authorization') != AUTHORIZATION:
        return JSONResponse({'errors': [{'message': 'unauthorized'}]}, status_code=401)
    payload = await request.json()
    return {
        'data': {'viewer': {'id': 'alice'}},
        'operationName': payload.get('operationName'),
    }


@app.get('/third-party')
async def third_party(request: Request):
    leaked = bool(request.headers.get('authorization'))
    origin = request.headers.get('origin') or '*'
    return Response(
        status_code=418 if leaked else 204,
        headers={
            'Access-Control-Allow-Origin': origin,
            'Vary': 'Origin',
            'X-Auth-Leaked': '1' if leaked else '0',
        },
    )


@app.get('/static/app.js')
async def app_js():
    source = r"""
(() => {
  localStorage.setItem('theme', 'dark-secret-value-never-persist');
  sessionStorage.setItem('workspace', 'tenant-a-secret-never-persist');
  window.addEventListener('message', () => {});
  window.postMessage({type: 'fixture-ready'}, '*');

  const sink = document.getElementById('sink');
  if (sink) sink.innerHTML = '<span>safe fixture content</span>';

  fetch('/api/profile?token=browser-query-secret&view=full')
    .then((response) => response.json())
    .catch(() => null);

  fetch('/graphql', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      operationName: 'Viewer',
      query: 'query Viewer($accountId: ID!, $secretToken: String!) { viewer { id } }',
      variables: {
        accountId: 'acct-secret-42',
        secretToken: 'graphql-secret-value-never-persist'
      }
    })
  }).catch(() => null);

  fetch('http://127.0.0.1:18084/third-party').catch(() => null);
  fetch('http://192.0.2.1/blocked').catch(() => null);

  const socket = new WebSocket('ws://' + location.host + '/ws');
  socket.addEventListener('open', () => socket.send('fixture-hello'));
  socket.addEventListener('message', () => socket.close());

  try {
    new WebSocket('ws://192.0.2.1/blocked-ws');
  } catch (_) {}

  try {
    if (typeof WebTransport === 'function') {
      new WebTransport('https://192.0.2.1/blocked-transport');
    }
  } catch (_) {}
})();
"""
    return Response(
        source,
        media_type='application/javascript',
        headers={'SourceMap': '/static/app.js.map'},
    )


@app.get('/static/app.js.map')
async def app_map():
    return JSONResponse({
        'version': 3,
        'file': 'app.js',
        'sources': ['app.ts'],
        'names': [],
        'mappings': '',
    })


@app.websocket('/ws')
async def websocket_fixture(websocket: WebSocket):
    await websocket.accept()
    try:
        await websocket.receive_text()
        await websocket.send_text('fixture-ack')
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass
