from __future__ import annotations

import pytest

from fastapi_app.services import scope_authorization as scope


@pytest.mark.parametrize(
    ('configured', 'target', 'expected'),
    [
        ('127.0.0.1', '127.0.0.1', True),
        ('127.0.0.0/24', '127.0.0.42', True),
        ('127.0.0.0/24', '127.0.1.42', False),
        ('2001:db8::/32', '2001:db8::42', True),
        ('2001:db8::/32', '2001:db9::42', False),
        ('example.com', 'example.com', True),
        ('example.com', 'api.example.com', False),
        ('*.example.com', 'api.example.com', True),
        ('*.example.com', 'example.com', False),
        ('*.example.com', 'api.internal.example.com', True),
        ('*', 'anything.example.com', False),
        ('example.com', 'https://example.com', True),
        ('example.com', 'https://user:pass@example.com', False),
        ('example.com', 'https://example.com/?redirect=https://evil.example', False),
        ('example.com', 'example.com\n.evil.example', False),
        ('xn--bcher-kva.example', 'bücher.example', True),
        ('example.com', 'example.com:443', True),
    ],
)
def test_target_scope_matrix(monkeypatch, configured: str, target: str, expected: bool):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', configured)
    assert scope.is_target_authorized(target) is expected


def test_empty_allowlist_fails_closed(monkeypatch):
    monkeypatch.delenv('AUTHORIZED_SCAN_TARGETS', raising=False)
    assert scope.is_target_authorized('127.0.0.1') is False


def test_invalid_configured_wildcard_fails_closed(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '*.')
    assert scope.is_target_authorized('api.example.com') is False


def test_url_scope_requires_http(monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'example.com')
    with pytest.raises(scope.ScopeAuthorizationError):
        scope.require_authorized_target('ftp://example.com', url=True)
