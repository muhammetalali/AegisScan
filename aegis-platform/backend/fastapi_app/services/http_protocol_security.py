from __future__ import annotations

from typing import Any

from django.db import transaction

from enterprise.web_security_models import WebSecurityObservation, WebSecurityValidationRun
from fastapi_app.services.web_security_foundation import CONTRACT_VERSION, canonical_digest, upsert_graph_snapshot


def _identity(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get('identity')
    return value if isinstance(value, dict) else {}


def _resource(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get('resource')
    return value if isinstance(value, dict) else {}


def _decision(allowed: bool) -> str:
    return WebSecurityObservation.Decision.ALLOWED if allowed else WebSecurityObservation.Decision.DENIED


def _norm_authority(value: Any) -> str:
    text = str(value or '').strip().lower()
    return text[:-1] if text.endswith('.') else text


def _norm_tokens(values: Any) -> list[str]:
    return [str(v).strip().lower() for v in (values or []) if str(v).strip()]


def _framing_failures(hop: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    protocol = str(hop.get('protocol') or '').lower()
    cls = [int(v) for v in (hop.get('content_length_values') or [])]
    transfer = _norm_tokens(hop.get('transfer_encodings'))
    te_values = _norm_tokens(hop.get('te_header_values'))
    connection = _norm_tokens(hop.get('connection_tokens'))
    body_len = hop.get('body_length_bytes')

    if cls and len(set(cls)) != 1:
        failures.append(f'{hop.get("ref")}: conflicting Content-Length values')
    if cls and body_len is not None and len(set(cls)) == 1 and cls[0] != int(body_len):
        failures.append(f'{hop.get("ref")}: Content-Length does not match observed body length')

    if protocol in {'http/1.0', 'http/1.1'}:
        if cls and transfer:
            failures.append(f'{hop.get("ref")}: Transfer-Encoding and Content-Length coexist')
        if transfer:
            if transfer[-1] != 'chunked':
                failures.append(f'{hop.get("ref")}: HTTP/1 transfer coding does not end in chunked')
            if transfer.count('chunked') != 1:
                failures.append(f'{hop.get("ref")}: duplicate or ambiguous chunked transfer coding')
    elif protocol in {'h2', 'h3'}:
        if transfer:
            failures.append(f'{hop.get("ref")}: Transfer-Encoding is prohibited in HTTP/2 or HTTP/3')
        if connection:
            failures.append(f'{hop.get("ref")}: connection-specific headers crossed an HTTP/2 or HTTP/3 hop')
        if any(value != 'trailers' for value in te_values):
            failures.append(f'{hop.get("ref")}: HTTP/2 or HTTP/3 TE value is not trailers')
        if not bool(hop.get('pseudo_headers_valid', True)):
            failures.append(f'{hop.get("ref")}: invalid HTTP/2 or HTTP/3 pseudo-header set')
        if not bool(hop.get('pseudo_headers_order_valid', True)):
            failures.append(f'{hop.get("ref")}: invalid pseudo-header ordering')

    authority = _norm_authority(hop.get('authority'))
    host = _norm_authority(hop.get('host'))
    if authority and host and authority != host:
        failures.append(f'{hop.get("ref")}: authority and Host disagree')
    if bool(hop.get('parser_accepted', True)) and not bool(hop.get('message_complete', True)):
        failures.append(f'{hop.get("ref")}: parser accepted an incomplete message')

    declared = set(_norm_tokens(hop.get('trailer_declared')))
    observed = set(_norm_tokens(hop.get('trailer_observed')))
    if observed - declared:
        failures.append(f'{hop.get("ref")}: undeclared trailers were observed')
    return failures


def _response_failures(response: dict[str, Any] | None) -> list[str]:
    if not response:
        return []
    synthetic = {
        'ref': 'response',
        'protocol': response.get('protocol'),
        'content_length_values': response.get('content_length_values'),
        'body_length_bytes': response.get('body_length_bytes'),
        'transfer_encodings': response.get('transfer_encodings'),
        'te_header_values': response.get('te_header_values'),
        'connection_tokens': response.get('connection_tokens'),
        'pseudo_headers_valid': True,
        'pseudo_headers_order_valid': True,
        'message_complete': True,
        'parser_accepted': True,
        'trailer_declared': response.get('trailer_declared'),
        'trailer_observed': response.get('trailer_observed'),
    }
    return _framing_failures(synthetic)


def evaluate_http_protocol_case(case: dict[str, Any]) -> dict[str, Any]:
    expected = bool(case.get('expected_allowed'))
    accepted = bool(case.get('server_accepted'))
    failures: list[str] = []
    if accepted != expected:
        failures.append('observed HTTP protocol decision does not match expected policy')

    identity = _identity(case)
    resource = _resource(case)
    if accepted and identity.get('tenant_ref') and resource.get('tenant_ref') and identity.get('tenant_ref') != resource.get('tenant_ref'):
        failures.append('cross-tenant HTTP protocol use was accepted')

    hops = [h for h in (case.get('hops') or []) if isinstance(h, dict)]
    for hop in hops:
        failures.extend(_framing_failures(hop))

    if hops:
        baseline_method = str(hops[0].get('method') or '').upper()
        baseline_path = str(hops[0].get('path') or '')
        baseline_authority = _norm_authority(hops[0].get('authority') or hops[0].get('host'))
        baseline_body = str(hops[0].get('semantic_body_sha256') or '')
        for hop in hops[1:]:
            ref = str(hop.get('ref') or 'hop')
            if str(hop.get('method') or '').upper() != baseline_method:
                failures.append(f'{ref}: method semantics changed across HTTP hops')
            if str(hop.get('path') or '') != baseline_path:
                failures.append(f'{ref}: path semantics changed across HTTP hops')
            authority = _norm_authority(hop.get('authority') or hop.get('host'))
            if baseline_authority and authority and authority != baseline_authority:
                failures.append(f'{ref}: authority semantics changed across HTTP hops')
            body_hash = str(hop.get('semantic_body_sha256') or '')
            if baseline_body and body_hash and body_hash != baseline_body:
                failures.append(f'{ref}: semantic body changed across HTTP translation')

    failures.extend(_response_failures(case.get('response') if isinstance(case.get('response'), dict) else None))

    hop_semantics = [{
        'ref': str(h.get('ref') or ''),
        'role': str(h.get('role') or ''),
        'protocol': str(h.get('protocol') or ''),
        'method': str(h.get('method') or '').upper(),
        'path_sha256': canonical_digest(str(h.get('path') or '')),
        'authority': _norm_authority(h.get('authority') or h.get('host')),
        'content_length_count': len(h.get('content_length_values') or []),
        'transfer_encodings': _norm_tokens(h.get('transfer_encodings')),
        'te_header_values': _norm_tokens(h.get('te_header_values')),
        'connection_tokens': _norm_tokens(h.get('connection_tokens')),
        'semantic_body_sha256': str(h.get('semantic_body_sha256') or ''),
        'parser_accepted': bool(h.get('parser_accepted', True)),
        'message_complete': bool(h.get('message_complete', True)),
    } for h in hops]
    semantic = {
        'hop_count': len(hops),
        'protocol_chain': [str(h.get('protocol') or '') for h in hops],
        'hops': hop_semantics,
        'response_protocol': str((case.get('response') or {}).get('protocol') or '') if isinstance(case.get('response'), dict) else '',
        'failures': failures,
    }
    return {
        'passed': not failures,
        'expected_allowed': expected,
        'observed_decision': _decision(accepted),
        'semantic': semantic,
        'evidence_fingerprint': canonical_digest(semantic),
        'reason': '; '.join(failures) if failures else 'HTTP protocol consistency invariants satisfied',
    }


def _project_graph(project, case: dict[str, Any], result: dict[str, Any]) -> None:
    identity = _identity(case)
    resource = _resource(case)
    identity_ref = str(identity.get('ref') or '')
    resource_ref = str(resource.get('ref') or '')
    endpoint = str(case.get('endpoint') or '')
    endpoint_ref = f'http-endpoint:{canonical_digest(endpoint)[:32]}'
    nodes = [
        {'plane': 'identity', 'kind': 'identity', 'external_ref': f'identity:{identity_ref}', 'label': identity_ref, 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'identity_type': identity.get('type'), 'role': identity.get('role')}, 'provenance': {'source': 'http_protocol_security'}},
        {'plane': 'application', 'kind': 'resource', 'external_ref': f'resource:{resource_ref}', 'label': resource_ref, 'protocol': 'http', 'tenant_ref': str(resource.get('tenant_ref') or ''), 'properties': {'resource_type': resource.get('type')}, 'provenance': {'source': 'http_protocol_security'}},
        {'plane': 'application', 'kind': 'endpoint', 'external_ref': endpoint_ref, 'label': endpoint, 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'last_validation_passed': result['passed'], 'evidence_fingerprint': result['evidence_fingerprint']}, 'provenance': {'source': 'http_protocol_security'}},
    ]
    edges = [
        {'source_ref': f'identity:{identity_ref}', 'target_ref': endpoint_ref, 'relation': 'invokes', 'properties': {'case_ref': case.get('ref')}, 'evidence_refs': [result['evidence_fingerprint']], 'provenance': {'source': 'http_protocol_security'}},
        {'source_ref': endpoint_ref, 'target_ref': f'resource:{resource_ref}', 'relation': 'operates_on', 'properties': {}, 'evidence_refs': [result['evidence_fingerprint']], 'provenance': {'source': 'http_protocol_security'}},
    ]
    previous = endpoint_ref
    for index, hop in enumerate(case.get('hops') or []):
        hop_ref = f'http-hop:{canonical_digest([case.get("ref"), index, hop.get("ref")])[:32]}'
        role = str(hop.get('role') or '')
        kind = 'reverse_proxy' if role in {'edge', 'gateway'} else 'service'
        nodes.append({'plane': 'application', 'kind': kind, 'external_ref': hop_ref, 'label': str(hop.get('ref') or role), 'protocol': str(hop.get('protocol') or ''), 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'role': role, 'protocol': hop.get('protocol')}, 'provenance': {'source': 'http_protocol_security'}})
        edges.append({'source_ref': previous, 'target_ref': hop_ref, 'relation': 'forwards_to', 'properties': {'hop_index': index}, 'evidence_refs': [result['evidence_fingerprint']], 'provenance': {'source': 'http_protocol_security'}})
        previous = hop_ref
    upsert_graph_snapshot(project, nodes, edges)


def run_http_protocol_security(project, actor_id: str, cases: list[dict[str, Any]], governance: dict[str, Any] | None = None):
    results = [evaluate_http_protocol_case(case) for case in cases]
    summary: dict[str, Any] = {'total': len(results), 'passed': sum(1 for r in results if r['passed']), 'failed': sum(1 for r in results if not r['passed'])}
    if governance:
        summary['governance'] = {'allowed': bool(governance.get('allowed')), 'credential_bindings': governance.get('credential_bindings', [])}
    with transaction.atomic():
        run = WebSecurityValidationRun.objects.create(project=project, kind=WebSecurityValidationRun.Kind.HTTP_PROTOCOL_SECURITY, status=WebSecurityValidationRun.Status.COMPLETED, contract_version=CONTRACT_VERSION, input_sha256=canonical_digest(cases), summary=summary, created_by_id=actor_id)
        observations = []
        for case, result in zip(cases, results, strict=True):
            identity, resource = _identity(case), _resource(case)
            row = WebSecurityObservation.objects.create(run=run, case_ref=str(case.get('ref') or ''), identity_ref=str(identity.get('ref') or ''), identity_type=str(identity.get('type') or ''), role=str(identity.get('role') or ''), tenant_ref=str(identity.get('tenant_ref') or ''), resource_ref=str(resource.get('ref') or ''), resource_tenant_ref=str(resource.get('tenant_ref') or ''), endpoint=str(case.get('endpoint') or ''), method=str(case.get('method') or ''), operation=str(case.get('operation') or 'request'), expected_allowed=result['expected_allowed'], observed_decision=result['observed_decision'], passed=result['passed'], semantic=result['semantic'], evidence_fingerprint=result['evidence_fingerprint'], reason=result['reason'])
            observations.append(row)
            _project_graph(project, case, result)
    return run, observations
