#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from fastapi_app.services.api_schema_security import parse_document, schema_url
from fastapi_app.services.pinned_http import PinnedHTTPResponse, get_pinned_same_origin, origin, request_pinned

SCHEMA = 'aegis.api-runtime-conformance.v1'
SAFE_METHODS = ('get', 'head')
_HEADER_NAME_RE = re.compile(r'^[!#$%&*+.^_`|~0-9A-Za-z-]{1,100}$')
_CONTROL_RE = re.compile(r'[\x00-\x1f\x7f]')


def _read_credential(path: str | None) -> str:
    if not path:
        return ''
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            secret = handle.read(8193)
    except OSError as exc:
        raise ValueError('credential file could not be read') from exc
    if len(secret) > 8192:
        raise ValueError('credential material exceeds 8192 bytes')
    secret = secret.strip()
    if not secret or '\r' in secret or '\n' in secret or '\x00' in secret:
        raise ValueError('credential material is invalid')
    return secret


def _local_ref(document: dict[str, Any], value: Any, *, depth: int = 0) -> Any:
    if depth > 12 or not isinstance(value, dict) or '$ref' not in value:
        return value
    ref = str(value.get('$ref') or '')
    if not ref.startswith('#/'):
        return value
    node: Any = document
    try:
        for token in ref[2:].split('/'):
            token = token.replace('~1', '/').replace('~0', '~')
            node = node[token]
    except (KeyError, TypeError):
        return value
    return _local_ref(document, node, depth=depth + 1)


def _security_schemes(document: dict[str, Any]) -> dict[str, Any]:
    components = document.get('components')
    if isinstance(components, dict) and isinstance(components.get('securitySchemes'), dict):
        return components['securitySchemes']
    legacy = document.get('securityDefinitions')
    return legacy if isinstance(legacy, dict) else {}


def _operation_security(document: dict[str, Any], operation: dict[str, Any]) -> Any:
    return operation.get('security') if 'security' in operation else document.get('security')


def _auth_headers(document: dict[str, Any], operation: dict[str, Any], secret: str) -> tuple[dict[str, str], str, str]:
    requirements = _operation_security(document, operation)
    if requirements is None or requirements == []:
        return {}, 'anonymous', ''
    if not isinstance(requirements, list):
        return {}, 'unsupported', 'invalid-security-requirement'
    if any(isinstance(item, dict) and not item for item in requirements):
        return {}, 'anonymous', ''
    if not secret:
        return {}, 'skipped', 'credential-required'

    schemes = _security_schemes(document)
    for requirement in requirements:
        if not isinstance(requirement, dict) or len(requirement) != 1:
            continue
        name = str(next(iter(requirement), ''))
        definition = _local_ref(document, schemes.get(name))
        if not isinstance(definition, dict):
            continue
        kind = str(definition.get('type') or '').lower()
        if kind == 'http' and str(definition.get('scheme') or '').lower() == 'bearer':
            return {'Authorization': f'Bearer {secret}'}, 'bearer', ''
        if kind in {'oauth2', 'openidconnect'}:
            return {'Authorization': f'Bearer {secret}'}, 'bearer', ''
        if kind == 'apikey' and str(definition.get('in') or '').lower() == 'header':
            header = str(definition.get('name') or '').strip()
            if _HEADER_NAME_RE.fullmatch(header):
                return {header: secret}, 'api-key-header', ''
    return {}, 'skipped', 'unsupported-security-scheme'


def _parameter_list(document: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for source in (path_item.get('parameters'), operation.get('parameters')):
        if not isinstance(source, list):
            continue
        for raw in source[:200]:
            item = _local_ref(document, raw)
            if not isinstance(item, dict):
                continue
            name = str(item.get('name') or '').strip()
            location = str(item.get('in') or '').strip().lower()
            if name and location in {'path', 'query', 'header'}:
                merged[(location, name)] = item
    return list(merged.values())


def _example_from_schema(schema: Any) -> tuple[Any, bool]:
    if not isinstance(schema, dict):
        return None, False
    for key in ('example', 'default'):
        if key in schema and schema[key] is not None:
            return schema[key], True
    enum = schema.get('enum')
    if isinstance(enum, list) and enum:
        return enum[0], True
    kind = str(schema.get('type') or '').lower()
    fmt = str(schema.get('format') or '').lower()
    if fmt == 'uuid':
        return '00000000-0000-4000-8000-000000000001', False
    if fmt == 'date':
        return '2000-01-01', False
    if fmt == 'date-time':
        return '2000-01-01T00:00:00Z', False
    if kind == 'integer':
        minimum = schema.get('minimum')
        return int(minimum) if isinstance(minimum, int) else 1, False
    if kind == 'number':
        minimum = schema.get('minimum')
        return float(minimum) if isinstance(minimum, (int, float)) else 1.0, False
    if kind == 'boolean':
        return True, False
    if kind == 'string' or not kind:
        minimum = schema.get('minLength')
        length = max(1, min(int(minimum), 32)) if isinstance(minimum, int) else 5
        return 'a' * length, False
    return None, False


def _parameter_value(document: dict[str, Any], parameter: dict[str, Any]) -> tuple[Any, bool]:
    if parameter.get('example') is not None:
        return parameter['example'], True
    examples = parameter.get('examples')
    if isinstance(examples, dict):
        for candidate in examples.values():
            resolved = _local_ref(document, candidate)
            if isinstance(resolved, dict) and resolved.get('value') is not None:
                return resolved['value'], True
    schema = _local_ref(document, parameter.get('schema'))
    if not isinstance(schema, dict):
        schema = parameter
    return _example_from_schema(schema)


def _string_value(value: Any) -> str:
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(',', ':'))
    return str(value)


def _build_request(
    document: dict[str, Any],
    target: str,
    path_template: str,
    path_item: dict[str, Any],
    operation: dict[str, Any],
    *,
    omit_query: str = '',
) -> tuple[str, list[str], list[str]]:
    if not path_template.startswith('/') or '://' in path_template or '?' in path_template or '#' in path_template or _CONTROL_RE.search(path_template):
        raise ValueError('OpenAPI operation path is not a safe origin-relative path')
    parameters = _parameter_list(document, path_item, operation)
    path_value = path_template
    query: list[tuple[str, str]] = []
    required_queries: list[str] = []
    synthetic: list[str] = []

    for parameter in parameters:
        location = str(parameter.get('in') or '').lower()
        name = str(parameter.get('name') or '').strip()
        value, explicit = _parameter_value(document, parameter)
        if location == 'path':
            token = '{' + name + '}'
            if token not in path_value or value is None:
                if token in path_value:
                    raise ValueError(f'Path parameter {name!r} has no bounded usable example')
                continue
            path_value = path_value.replace(token, quote(_string_value(value), safe=''))
            if not explicit:
                synthetic.append(f'path:{name}')
        elif location == 'query':
            required = bool(parameter.get('required'))
            if required:
                required_queries.append(name)
            if name == omit_query or value is None:
                continue
            if required or explicit:
                query.append((name, _string_value(value)))
                if not explicit:
                    synthetic.append(f'query:{name}')

    if '{' in path_value or '}' in path_value:
        raise ValueError('OpenAPI path contains unresolved template parameters')
    target_parts = urlsplit(target)
    prefix = target_parts.path.rstrip('/') if target_parts.path not in {'', '/'} else ''
    full_path = f'{prefix}{path_value}' or '/'
    request_url = urlunsplit((target_parts.scheme, target_parts.netloc, full_path, urlencode(query, doseq=True), ''))
    if origin(request_url) != origin(target):
        raise ValueError('OpenAPI operation escaped the authorized API origin')
    return request_url, required_queries, synthetic


def _response_definition(document: dict[str, Any], operation: dict[str, Any], status: int) -> dict[str, Any] | None:
    responses = operation.get('responses')
    if not isinstance(responses, dict):
        return None
    exact = responses.get(str(status)) or responses.get(status)
    if isinstance(exact, dict):
        return _local_ref(document, exact)
    wildcard = responses.get(f'{status // 100}XX') or responses.get(f'{status // 100}xx')
    if isinstance(wildcard, dict):
        return _local_ref(document, wildcard)
    default = responses.get('default')
    return _local_ref(document, default) if isinstance(default, dict) else None


def _expected_content_types(document: dict[str, Any], operation: dict[str, Any], response: dict[str, Any]) -> set[str]:
    content = response.get('content')
    if isinstance(content, dict):
        return {str(item).split(';', 1)[0].strip().lower() for item in content if str(item).strip()}
    produces = operation.get('produces') or document.get('produces')
    if isinstance(produces, list):
        return {str(item).split(';', 1)[0].strip().lower() for item in produces if str(item).strip()}
    return set()


def _response_schema(document: dict[str, Any], response: dict[str, Any], content_type: str) -> dict[str, Any] | None:
    content = response.get('content')
    if isinstance(content, dict):
        chosen: Any = None
        if content_type in content:
            chosen = content.get(content_type)
        elif content_type.endswith('+json'):
            chosen = content.get('application/json')
        elif 'application/json' in content:
            chosen = content.get('application/json')
        if isinstance(chosen, dict):
            schema = _local_ref(document, chosen.get('schema'))
            return schema if isinstance(schema, dict) else None
    schema = _local_ref(document, response.get('schema'))
    return schema if isinstance(schema, dict) else None


def _json_type_matches(kind: str, value: Any) -> bool:
    return {
        'object': isinstance(value, dict),
        'array': isinstance(value, list),
        'string': isinstance(value, str),
        'integer': isinstance(value, int) and not isinstance(value, bool),
        'number': isinstance(value, (int, float)) and not isinstance(value, bool),
        'boolean': isinstance(value, bool),
        'null': value is None,
    }.get(kind, True)


def _shape_errors(document: dict[str, Any], schema: Any, value: Any, *, path: str = '$', depth: int = 0) -> list[str]:
    if depth > 12:
        return []
    schema = _local_ref(document, schema)
    if not isinstance(schema, dict):
        return []
    errors: list[str] = []
    kind = str(schema.get('type') or '').lower()
    if kind and not _json_type_matches(kind, value):
        return [f'{path}: expected {kind}']
    enum = schema.get('enum')
    if isinstance(enum, list) and value not in enum:
        errors.append(f'{path}: value is outside declared enum')
    if isinstance(value, dict):
        required = schema.get('required')
        if isinstance(required, list):
            for name in required[:100]:
                if str(name) not in value:
                    errors.append(f'{path}: missing required property {str(name)[:100]}')
                    if len(errors) >= 20:
                        return errors
        properties = schema.get('properties')
        if isinstance(properties, dict):
            for name, child in list(properties.items())[:200]:
                if str(name) in value:
                    errors.extend(_shape_errors(document, child, value[str(name)], path=f'{path}.{str(name)[:100]}', depth=depth + 1))
                    if len(errors) >= 20:
                        return errors[:20]
    elif isinstance(value, list) and 'items' in schema:
        for index, item in enumerate(value[:20]):
            errors.extend(_shape_errors(document, schema.get('items'), item, path=f'{path}[{index}]', depth=depth + 1))
            if len(errors) >= 20:
                return errors[:20]
    return errors[:20]


def _finding(rule_id: str, title: str, severity: str, description: str, remediation: str, **extra: Any) -> dict[str, Any]:
    return {
        'kind': 'api-runtime-security-finding',
        'rule_id': rule_id,
        'title': title,
        'severity': severity,
        'confidence': extra.pop('confidence', 'medium'),
        'category': 'api-runtime-security',
        'description': description,
        'remediation': remediation,
        **extra,
    }


def _baseline_findings(
    document: dict[str, Any],
    method: str,
    path_template: str,
    operation: dict[str, Any],
    response: PinnedHTTPResponse,
    synthetic_inputs: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    location = f'paths.{path_template}.{method}'
    if response.status >= 500:
        findings.append(_finding(
            'api.runtime.server-error-on-conformant-read',
            'Documented read operation returned a server error',
            'medium',
            f'{method.upper()} {path_template} returned HTTP {response.status} for a bounded schema-derived request.',
            'Harden request validation and error handling so documented read operations fail predictably without HTTP 5xx responses.',
            location=location, method=method.upper(), path=path_template, status=response.status,
            confidence='medium' if synthetic_inputs else 'high',
        ))
    definition = _response_definition(document, operation, response.status)
    if definition is None:
        findings.append(_finding(
            'api.runtime.undocumented-response-status',
            'Runtime status is not declared by the API contract',
            'low',
            f'{method.upper()} {path_template} returned HTTP {response.status}, which has no exact, class, or default response in the contract.',
            'Align runtime behavior with documented response statuses or update the contract to describe intentional behavior.',
            location=location, method=method.upper(), path=path_template, status=response.status,
        ))
        return findings

    expected_types = _expected_content_types(document, operation, definition)
    actual_type = response.content_type
    if expected_types and actual_type and actual_type not in expected_types and not (
        actual_type.endswith('+json') and 'application/json' in expected_types
    ):
        findings.append(_finding(
            'api.runtime.response-content-type-mismatch',
            'Runtime response content type differs from the API contract',
            'low',
            f'{method.upper()} {path_template} returned {actual_type!r}; the matched response declares {sorted(expected_types)[:10]!r}.',
            'Return one of the contract-declared media types or update the contract when the runtime media type is intentional.',
            location=location, method=method.upper(), path=path_template, status=response.status,
        ))

    schema = _response_schema(document, definition, actual_type)
    if schema and response.body and (actual_type == 'application/json' or actual_type.endswith('+json')):
        try:
            value = json.loads(response.body.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            findings.append(_finding(
                'api.runtime.invalid-json-response',
                'Runtime returned invalid JSON for a JSON contract response',
                'medium',
                f'{method.upper()} {path_template} declared a JSON response but returned a body that could not be parsed as JSON.',
                'Return syntactically valid JSON whenever the response media type is JSON.',
                location=location, method=method.upper(), path=path_template, status=response.status,
                confidence='high',
            ))
        else:
            errors = _shape_errors(document, schema, value)
            if errors:
                findings.append(_finding(
                    'api.runtime.response-shape-mismatch',
                    'Runtime JSON response violates declared schema constraints',
                    'medium',
                    f'{method.upper()} {path_template} returned JSON that violates bounded structural checks from the matched response schema.',
                    'Align response serialization with the OpenAPI response schema and add contract tests for required fields and declared types.',
                    location=location, method=method.upper(), path=path_template, status=response.status,
                    confidence='high', validation_errors=errors[:20],
                ))
    return findings


def validate_runtime(
    document: dict[str, Any],
    target: str,
    *,
    credential: str = '',
    timeout: int = 10,
    max_response_bytes: int = 262144,
    max_operations: int = 25,
) -> dict[str, Any]:
    if not 1 <= max_operations <= 50:
        raise ValueError('max_operations must be between 1 and 50')
    paths = document.get('paths')
    if not isinstance(paths, dict):
        raise ValueError('OpenAPI paths must be an object')

    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    executed = 0
    skipped = 0
    errors = 0

    for path_template, raw_path_item in paths.items():
        if executed >= max_operations:
            break
        path_item = _local_ref(document, raw_path_item)
        if not isinstance(path_item, dict):
            continue
        for method in SAFE_METHODS:
            if executed >= max_operations:
                break
            operation = _local_ref(document, path_item.get(method))
            if not isinstance(operation, dict):
                continue
            auth_headers, auth_mode, skip_reason = _auth_headers(document, operation, credential)
            if skip_reason:
                skipped += 1
                observations.append({
                    'kind': 'api-runtime-operation-skip', 'method': method.upper(),
                    'path': str(path_template)[:2048], 'reason': skip_reason,
                })
                continue
            try:
                request_url, required_queries, synthetic = _build_request(
                    document, target, str(path_template), path_item, operation,
                )
                response = request_pinned(
                    method.upper(), request_url, headers=auth_headers,
                    timeout=timeout, max_body_bytes=max_response_bytes,
                )
            except Exception as exc:
                errors += 1
                observations.append({
                    'kind': 'api-runtime-operation-error', 'method': method.upper(),
                    'path': str(path_template)[:2048], 'error': str(exc)[:1000],
                })
                continue

            executed += 1
            body_sha256 = hashlib.sha256(response.body).hexdigest()
            observations.append({
                'kind': 'api-runtime-operation',
                'method': method.upper(),
                'path': str(path_template)[:2048],
                'status': response.status,
                'content_type': response.content_type,
                'body_bytes': len(response.body),
                'body_sha256': body_sha256,
                'resolved_ip': response.resolved_ip,
                'auth_mode': auth_mode,
                'synthetic_inputs': synthetic[:50],
            })
            findings.extend(_baseline_findings(document, method, str(path_template), operation, response, synthetic))

            if 200 <= response.status < 300 and required_queries:
                omitted = required_queries[0]
                try:
                    negative_url, _, _ = _build_request(
                        document, target, str(path_template), path_item, operation,
                        omit_query=omitted,
                    )
                    negative = request_pinned(
                        method.upper(), negative_url, headers=auth_headers,
                        timeout=timeout, max_body_bytes=max_response_bytes,
                    )
                    observations.append({
                        'kind': 'api-runtime-negative-case',
                        'case': 'missing-required-query',
                        'method': method.upper(),
                        'path': str(path_template)[:2048],
                        'parameter': omitted[:200],
                        'status': negative.status,
                        'resolved_ip': negative.resolved_ip,
                    })
                    if 200 <= negative.status < 300:
                        findings.append(_finding(
                            'api.runtime.required-query-not-enforced',
                            'Required query parameter was not enforced at runtime',
                            'low',
                            f'{method.upper()} {path_template} still returned HTTP {negative.status} after required query parameter {omitted!r} was omitted.',
                            'Enforce contract-required request parameters consistently at the API boundary or mark the parameter optional in the contract.',
                            location=f'paths.{path_template}.{method}.parameters.{omitted}',
                            method=method.upper(), path=str(path_template), parameter=omitted,
                            status=negative.status, confidence='medium',
                        ))
                except Exception as exc:
                    observations.append({
                        'kind': 'api-runtime-negative-case-error',
                        'case': 'missing-required-query', 'method': method.upper(),
                        'path': str(path_template)[:2048], 'parameter': omitted[:200],
                        'error': str(exc)[:1000],
                    })

    unique: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for item in findings:
        key = (
            str(item.get('rule_id') or ''), str(item.get('location') or ''),
            str(item.get('method') or ''), str(item.get('path') or ''),
            str(item.get('parameter') or ''),
        )
        unique[key] = item
    bounded_findings = list(unique.values())[:1000]
    summary = {
        'kind': 'api-runtime-summary',
        'executed_operations': executed,
        'skipped_operations': skipped,
        'operation_errors': errors,
        'finding_count': len(bounded_findings),
        'safe_methods': [item.upper() for item in SAFE_METHODS],
        'max_operations': max_operations,
    }
    target_origin = origin(target)
    return {
        'schema': SCHEMA,
        'target_origin': f'{target_origin[0]}://{target_origin[1]}:{target_origin[2]}',
        'observations': [summary, *observations[:2000], *bounded_findings],
        'finding_count': len(bounded_findings),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AegisScan bounded safe OpenAPI runtime conformance validator')
    parser.add_argument('target_url')
    parser.add_argument('--spec-path', default='/openapi.json')
    parser.add_argument('--max-spec-bytes', type=int, default=1048576)
    parser.add_argument('--max-response-bytes', type=int, default=262144)
    parser.add_argument('--max-operations', type=int, default=25)
    parser.add_argument('--timeout-seconds', type=int, default=10)
    parser.add_argument('--credential-file', default='')
    args = parser.parse_args(argv)
    if not 65536 <= args.max_spec_bytes <= 2097152:
        raise SystemExit('max-spec-bytes must be between 65536 and 2097152')
    if not 1024 <= args.max_response_bytes <= 1048576:
        raise SystemExit('max-response-bytes must be between 1024 and 1048576')
    if not 1 <= args.max_operations <= 50:
        raise SystemExit('max-operations must be between 1 and 50')
    if not 2 <= args.timeout_seconds <= 30:
        raise SystemExit('timeout-seconds must be between 2 and 30')
    try:
        credential = _read_credential(args.credential_file or None)
        spec_url = schema_url(args.target_url, args.spec_path)
        schema_response = get_pinned_same_origin(
            spec_url,
            headers={'Accept': 'application/json, application/yaml, text/yaml'},
            timeout=args.timeout_seconds,
            max_body_bytes=args.max_spec_bytes,
            max_redirects=1,
        )
        if not 200 <= schema_response.status < 300:
            raise RuntimeError(f'API schema request returned HTTP {schema_response.status}')
        document = parse_document(schema_response.body)
        payload = validate_runtime(
            document,
            args.target_url,
            credential=credential,
            timeout=args.timeout_seconds,
            max_response_bytes=args.max_response_bytes,
            max_operations=args.max_operations,
        )
        payload['spec'] = {
            'url': spec_url,
            'status': schema_response.status,
            'content_type': schema_response.content_type,
            'document_sha256': hashlib.sha256(schema_response.body).hexdigest(),
            'document_bytes': len(schema_response.body),
            'resolved_ip': schema_response.resolved_ip,
        }
    except Exception as exc:
        print(json.dumps({'schema': SCHEMA, 'error': str(exc)[:2000]}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(payload, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
