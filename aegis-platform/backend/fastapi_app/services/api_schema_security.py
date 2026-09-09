#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
import yaml

SCHEMA = 'aegis.api-schema-security.v1'
METHODS = ('get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace')
MUTATING = {'post', 'put', 'patch', 'delete'}


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower()
    if scheme not in {'http', 'https'} or not host or parsed.username or parsed.password:
        raise ValueError('target must be an absolute HTTP(S) URL without embedded credentials')
    return scheme, host, parsed.port or (443 if scheme == 'https' else 80)


def schema_url(target: str, spec_path: str) -> str:
    part = urlsplit(spec_path)
    if part.scheme or part.netloc or part.fragment or not part.path.startswith('/'):
        raise ValueError('spec_path must be an absolute path on the authorized target origin')
    result = urljoin(target, part.path + (f'?{part.query}' if part.query else ''))
    if _origin(result) != _origin(target):
        raise ValueError('spec_path must remain on the authorized target origin')
    return result


def fetch_schema(target: str, spec_path: str, max_bytes: int, timeout: int) -> tuple[str, bytes, str]:
    url = schema_url(target, spec_path)
    response = requests.get(
        url,
        headers={'User-Agent': 'AegisScan-APISchemaSecurity/1.0', 'Accept': 'application/json, application/yaml, text/yaml'},
        timeout=timeout,
        allow_redirects=False,
    )
    if response.is_redirect:
        location = response.headers.get('Location', '')
        redirected = urljoin(url, location)
        if not location or _origin(redirected) != _origin(url):
            raise RuntimeError('API schema redirect crossed the authorized target origin')
        response = requests.get(redirected, headers={'User-Agent': 'AegisScan-APISchemaSecurity/1.0'}, timeout=timeout, allow_redirects=False)
        url = redirected
    response.raise_for_status()
    body = response.content
    if len(body) > max_bytes:
        raise ValueError(f'API schema exceeds max_spec_bytes={max_bytes}')
    return url, body, response.headers.get('Content-Type', '').split(';', 1)[0]


def parse_document(body: bytes) -> dict[str, Any]:
    text = body.decode('utf-8')
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise ValueError('API schema root must be an object')
    if not (str(value.get('openapi') or '').startswith('3.') or str(value.get('swagger') or '') == '2.0'):
        raise ValueError('only OpenAPI 3.x and Swagger 2.0 are supported')
    if not isinstance(value.get('paths', {}), dict):
        raise ValueError('paths must be an object')
    return value


def _schemes(document: dict[str, Any]) -> dict[str, Any]:
    components = document.get('components')
    if isinstance(components, dict) and isinstance(components.get('securitySchemes'), dict):
        return components['securitySchemes']
    legacy = document.get('securityDefinitions')
    return legacy if isinstance(legacy, dict) else {}


def _refs(requirements: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(requirements, list):
        for item in requirements:
            if isinstance(item, dict):
                result.update(str(key) for key in item if str(key))
    return result


def _finding(rule_id: str, title: str, severity: str, description: str, remediation: str, **extra: Any) -> dict[str, Any]:
    return {
        'kind': 'api-schema-security-finding', 'rule_id': rule_id, 'title': title,
        'severity': severity, 'confidence': extra.pop('confidence', 'high'), 'category': 'api-security',
        'description': description, 'remediation': remediation, **extra,
    }


def analyze(document: dict[str, Any], spec_url: str, digest: str, size: int) -> dict[str, Any]:
    schemes = _schemes(document)
    findings: list[dict[str, Any]] = []
    paths = document.get('paths', {})
    if len(paths) > 10000:
        raise ValueError('API schema contains more than 10000 paths')

    for name, definition in list(schemes.items())[:500]:
        if isinstance(definition, dict) and str(definition.get('type', '')).lower() == 'apikey' and str(definition.get('in', '')).lower() == 'query':
            findings.append(_finding(
                'api.openapi.api-key-in-query', 'API key is declared in the URL query string', 'high',
                f'Security scheme {name!r} places credentials in query parameters, which can be retained in logs and intermediary metadata.',
                'Move API credentials to a protected request header and rotate keys previously transmitted in URLs.',
                cwe_id='CWE-598', owasp_category='A02:2021-Cryptographic Failures', location=f'securitySchemes.{name}',
            ))

    global_security = document.get('security')
    global_refs = _refs(global_security)
    for name in sorted(global_refs - set(schemes)):
        findings.append(_finding(
            'api.openapi.undefined-security-scheme', 'Security requirement references an undefined scheme', 'medium',
            f'Global security requirement references {name!r}, but the contract defines no matching security scheme.',
            'Define the referenced security scheme or correct the security requirement name.',
            cwe_id='CWE-284', owasp_category='A01:2021-Broken Access Control', location='security',
        ))

    operation_count = 0
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            operation_count += 1
            if operation_count > 20000:
                raise ValueError('API schema contains more than 20000 operations')
            effective = operation.get('security') if 'security' in operation else global_security
            refs = _refs(effective)
            anonymous = effective == [] or (isinstance(effective, list) and any(isinstance(entry, dict) and not entry for entry in effective))
            for name in sorted(refs - set(schemes)):
                findings.append(_finding(
                    'api.openapi.undefined-security-scheme', 'Security requirement references an undefined scheme', 'medium',
                    f'{method.upper()} {path} references {name!r}, but the contract defines no matching security scheme.',
                    'Define the referenced scheme or correct the operation security requirement.',
                    cwe_id='CWE-284', owasp_category='A01:2021-Broken Access Control', location=f'paths.{path}.{method}.security', method=method.upper(), path=str(path),
                ))
            if method in MUTATING and global_refs and 'security' in operation and anonymous:
                findings.append(_finding(
                    'api.openapi.explicit-public-state-change', 'State-changing operation explicitly disables inherited authentication', 'medium',
                    f'{method.upper()} {path} overrides API-wide security with anonymous access and therefore creates an explicit authorization-boundary exception.',
                    'Require an appropriate security scheme or document and independently verify the intentional anonymous exception.',
                    cwe_id='CWE-862', owasp_category='A01:2021-Broken Access Control', confidence='medium', location=f'paths.{path}.{method}.security', method=method.upper(), path=str(path),
                ))

    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        unique[(str(finding.get('rule_id')), str(finding.get('location')))] = finding
    bounded = list(unique.values())[:2000]
    summary = {
        'kind': 'api-schema-summary', 'spec_url': spec_url, 'document_sha256': digest, 'document_bytes': size,
        'version': str(document.get('openapi') or document.get('swagger') or ''), 'path_count': len(paths),
        'operation_count': operation_count, 'security_scheme_count': len(schemes), 'finding_count': len(bounded),
    }
    return {'schema': SCHEMA, 'target_url': spec_url, 'observations': [summary, *bounded], 'finding_count': len(bounded)}


def analyze_bytes(body: bytes, spec_url: str) -> dict[str, Any]:
    return analyze(parse_document(body), spec_url, hashlib.sha256(body).hexdigest(), len(body))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AegisScan defensive OpenAPI contract security analyzer')
    parser.add_argument('target_url')
    parser.add_argument('--spec-path', default='/openapi.json')
    parser.add_argument('--max-spec-bytes', type=int, default=1048576)
    parser.add_argument('--timeout-seconds', type=int, default=10)
    args = parser.parse_args(argv)
    if not 65536 <= args.max_spec_bytes <= 2097152:
        raise SystemExit('max-spec-bytes must be between 65536 and 2097152')
    if not 2 <= args.timeout_seconds <= 30:
        raise SystemExit('timeout-seconds must be between 2 and 30')
    try:
        url, body, content_type = fetch_schema(args.target_url, args.spec_path, args.max_spec_bytes, args.timeout_seconds)
        payload = analyze_bytes(body, url)
        payload['content_type'] = content_type
    except Exception as exc:  # fail closed; Celery records stderr and non-zero status as evidence
        print(json.dumps({'schema': SCHEMA, 'error': str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(payload, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
