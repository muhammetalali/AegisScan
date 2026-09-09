from __future__ import annotations

from types import SimpleNamespace

from fastapi_app.services import pinned_http


class _FakeSocket:
    def __init__(self, connects: list[tuple]):
        self._connects = connects

    def settimeout(self, _timeout):
        return None

    def connect(self, address):
        self._connects.append(address)

    def close(self):
        return None


class _FakeResponse:
    status = 200

    def getheader(self, _name):
        return None

    def read(self, _size):
        return b'{}'

    def getheaders(self):
        return [('Content-Type', 'application/json')]


class _FakeConnection:
    def __init__(self, _host, _port, timeout=None):
        self.sock = None
        self.timeout = timeout

    def request(self, _method, _path, headers=None):
        assert headers is not None

    def getresponse(self):
        return _FakeResponse()

    def close(self):
        return None


def test_reused_destination_does_not_resolve_dns_again(monkeypatch):
    authorization_calls: list[bool] = []
    connects: list[tuple] = []

    def authorize(_target, *, url=False, resolve_dns=False):
        assert url is True
        authorization_calls.append(resolve_dns)
        if resolve_dns:
            if authorization_calls.count(True) > 1:
                raise AssertionError('DNS was resolved more than once for the pinned operation')
            return ('192.0.2.40',)
        return ()

    monkeypatch.setattr(pinned_http, 'require_authorized_target', authorize)
    monkeypatch.setattr(pinned_http.http.client, 'HTTPConnection', _FakeConnection)
    monkeypatch.setattr(
        pinned_http.socket,
        'socket',
        lambda *_args, **_kwargs: _FakeSocket(connects),
    )

    destination = pinned_http.pin_http_destination('http://cluster.example.test:8080')
    first = pinned_http.request_pinned(
        'GET',
        'http://cluster.example.test:8080/version',
        destination=destination,
    )
    second = pinned_http.request_pinned(
        'GET',
        'http://cluster.example.test:8080/api/v1/pods?limit=1000',
        destination=destination,
    )

    assert first.resolved_ip == second.resolved_ip == '192.0.2.40'
    assert authorization_calls == [True, False, False]
    assert connects == [('192.0.2.40', 8080), ('192.0.2.40', 8080)]


def test_custom_tls_context_preserves_logical_sni(monkeypatch):
    connects: list[tuple] = []
    wrapped: list[str] = []

    monkeypatch.setattr(
        pinned_http,
        'require_authorized_target',
        lambda _target, *, url=False, resolve_dns=False: ('198.51.100.17',) if resolve_dns else (),
    )
    monkeypatch.setattr(pinned_http.http.client, 'HTTPConnection', _FakeConnection)
    monkeypatch.setattr(
        pinned_http.socket,
        'socket',
        lambda *_args, **_kwargs: _FakeSocket(connects),
    )

    context = SimpleNamespace(
        wrap_socket=lambda sock, *, server_hostname: (wrapped.append(server_hostname) or sock)
    )
    destination = pinned_http.pin_http_destination('https://cluster.example.test:6443')
    response = pinned_http.request_pinned(
        'GET',
        'https://cluster.example.test:6443/version',
        destination=destination,
        ssl_context=context,
    )

    assert response.status == 200
    assert connects == [('198.51.100.17', 6443)]
    assert wrapped == ['cluster.example.test']


def test_reused_destination_rejects_cross_origin(monkeypatch):
    monkeypatch.setattr(
        pinned_http,
        'require_authorized_target',
        lambda _target, *, url=False, resolve_dns=False: ('192.0.2.10',) if resolve_dns else (),
    )
    destination = pinned_http.pin_http_destination('https://cluster.example.test:6443')

    try:
        pinned_http.request_pinned(
            'GET',
            'https://other.example.test:6443/version',
            destination=destination,
        )
    except ValueError as exc:
        assert 'does not match the requested origin' in str(exc)
    else:
        raise AssertionError('cross-origin reuse must fail closed')
