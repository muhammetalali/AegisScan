"""Minimal fail-closed client for the canonical AegisScan platform API."""
from __future__ import annotations

import json
import uuid
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import quote
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


    def capability_plan(self, project_id: str, asset_id: str, depth: str = 'standard') -> dict:
        if depth not in {'quick', 'standard', 'deep', 'comprehensive'}:
            raise PlatformClientError(f'Unsupported governed execution depth: {depth}')
        project = quote(str(project_id).strip(), safe='')
        asset = quote(str(asset_id).strip(), safe='')
        if not project or not asset:
            raise PlatformClientError('project_id and asset_id are required')
        result = self.request(
            'GET',
            f'/api/v1/capabilities/plan/{asset}?project_id={project}&depth={quote(depth, safe="")}',
        )
        if not isinstance(result, dict) or not isinstance(result.get('plan'), list):
            raise PlatformClientError('Capability plan returned an invalid response contract')
        return result

    def execute_capability(
        self,
        *,
        project_id: str,
        asset_id: str,
        capability_id: str,
        depth: str = 'standard',
        options: dict | None = None,
        credential_refs: list[str] | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
    ) -> dict:
        if depth not in {'quick', 'standard', 'deep', 'comprehensive'}:
            raise PlatformClientError(f'Unsupported governed execution depth: {depth}')
        project = str(project_id).strip()
        asset = str(asset_id).strip()
        capability = str(capability_id).strip()
        if not project or not asset or not capability:
            raise PlatformClientError('project_id, asset_id and capability_id are required')

        idem = str(idempotency_key or '').strip() or f'client-{uuid.uuid4()}'
        correlation = str(correlation_id or '').strip() or f'client-corr-{uuid.uuid4()}'
        payload = {
            'project_id': project,
            'asset_id': asset,
            'depth': depth,
            'options': dict(options or {}),
            'credential_refs': [str(item).strip() for item in (credential_refs or []) if str(item).strip()],
            'idempotency_key': idem,
            'correlation_id': correlation,
        }
        result = self.request(
            'POST',
            f'/api/v1/capabilities/{quote(capability, safe="")}/execute',
            payload,
        )
        if not isinstance(result, dict):
            raise PlatformClientError('Governed capability execution returned an invalid response contract')
        contract = result.get('execution_contract')
        scan = result.get('scan')
        if not isinstance(contract, dict) or contract.get('contract_version') != '1.0':
            raise PlatformClientError('Governed capability execution omitted the versioned execution contract')
        if not isinstance(scan, dict) or not str(scan.get('id') or '').strip():
            raise PlatformClientError('Governed capability execution omitted the canonical Scan identity')
        if str(contract.get('capability_id') or '').strip() == '':
            raise PlatformClientError('Governed capability execution omitted the resolved capability identity')
        policy_fingerprint = str(contract.get('policy_fingerprint') or '')
        if len(policy_fingerprint) != 64:
            raise PlatformClientError('Governed capability execution returned an invalid policy fingerprint')
        return result
