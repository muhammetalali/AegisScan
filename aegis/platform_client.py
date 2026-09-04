"""Minimal fail-closed client for the canonical AegisScan platform API."""
from __future__ import annotations

import json
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.request import HTTPCookieProcessor, Request, build_opener


class PlatformClientError(RuntimeError):
    pass


class PlatformClient:
    def __init__(self, base_url: str, timeout: float = 20.0):
        self.base_url = base_url.rstrip('/')
        if not self.base_url.startswith(('http://', 'https://')):
            raise PlatformClientError('Platform base URL must use http or https')
        self.timeout = timeout
        self.cookies = CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookies))
        self.csrf_token = ''

    def request(self, method: str, path: str, payload: dict | None = None) -> dict | list:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {'Accept': 'application/json'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if method.upper() not in {'GET', 'HEAD', 'OPTIONS'} and self.csrf_token:
            headers['X-CSRFToken'] = self.csrf_token
            headers['Referer'] = f'{self.base_url}/'
        request = Request(f'{self.base_url}{path}', data=data, headers=headers, method=method.upper())
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read().decode('utf-8')
        except HTTPError as exc:
            body = exc.read().decode('utf-8', errors='replace')
            raise PlatformClientError(f'{method} {path} failed with HTTP {exc.code}: {body[:500]}') from exc
        except URLError as exc:
            raise PlatformClientError(f'{method} {path} transport failure: {exc.reason}') from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PlatformClientError(f'{method} {path} returned non-JSON content') from exc

    def login(self, email: str, password: str) -> None:
        csrf = self.request('GET', '/api/v1/auth/csrf/')
        self.csrf_token = str(csrf.get('csrfToken') or '') if isinstance(csrf, dict) else ''
        if not self.csrf_token:
            raise PlatformClientError('Platform did not issue a CSRF token')
        result = self.request('POST', '/api/v1/auth/login/', {'email': email, 'password': password})
        if not isinstance(result, dict):
            raise PlatformClientError('Login returned an invalid response contract')

    def authenticated_status(self, email: str, password: str) -> dict:
        ready = self.request('GET', '/ready')
        health = self.request('GET', '/health')
        self.login(email, password)
        projects = self.request('GET', '/api/v1/projects/')
        rows = projects.get('results', []) if isinstance(projects, dict) else projects
        if not isinstance(rows, list):
            raise PlatformClientError('Projects endpoint returned an invalid collection contract')
        return {'ready': ready, 'health': health, 'authenticated': True, 'project_count': len(rows), 'source': 'platform-api'}
