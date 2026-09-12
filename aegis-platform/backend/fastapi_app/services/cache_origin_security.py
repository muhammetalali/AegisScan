
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


def _cache_failures(cache: dict[str, Any]) -> list[str]:
    ref = str(cache.get('ref') or 'cache')
    failures: list[str] = []
    required = {str(item) for item in (cache.get('required_key_dimensions') or [])}
    observed = {str(item) for item in (cache.get('observed_key_dimensions') or [])}
    missing = sorted(required - observed)
    if missing:
        failures.append(f'{ref}: cache key omits required dimensions: {", ".join(missing)}')
    if bool(cache.get('shared')) and bool(cache.get('cache_hit')):
        if bool(cache.get('response_private')):
            failures.append(f'{ref}: shared cache served a response marked private')
        if bool(cache.get('response_no_store')):
            failures.append(f'{ref}: shared cache served a response marked no-store')
        if bool(cache.get('authenticated_response')):
            isolation = {'authorization', 'cookie', 'tenant', 'identity'} & observed
            if not isolation and not bool(cache.get('response_private')) and not bool(cache.get('response_no_store')):
                failures.append(f'{ref}: authenticated response is shared without identity-aware cache partitioning')
    return failures


def _proxy_failures(hop: dict[str, Any]) -> list[str]:
    ref = str(hop.get('ref') or 'proxy')
    failures: list[str] = []
    trusted = bool(hop.get('source_trusted'))
    present = bool(hop.get('forwarded_headers_present'))
    accepted = bool(hop.get('forwarded_headers_accepted'))
    selected = any(bool(hop.get(key)) for key in (
        'host_selected_from_forwarded', 'scheme_selected_from_forwarded',
        'client_identity_selected_from_forwarded',
    ))
    if present and accepted and not trusted:
        failures.append(f'{ref}: forwarded headers from an untrusted source were accepted')
    if accepted and not bool(hop.get('forwarded_chain_valid', True)):
        failures.append(f'{ref}: invalid forwarded chain was accepted')
    if selected and not trusted:
        failures.append(f'{ref}: routing or client identity was selected from an untrusted forwarded header')
    return failures


def _origin_failures(origin: dict[str, Any]) -> list[str]:
    ref = str(origin.get('ref') or 'origin')
    failures: list[str] = []
    if str(origin.get('selected_origin_ref') or '') != str(origin.get('expected_origin_ref') or ''):
        failures.append(f'{ref}: selected origin does not match governed expected origin')
    if not bool(origin.get('authority_matches_request', True)):
        failures.append(f'{ref}: selected origin authority does not match governed request authority')
    if bool(origin.get('host_override_present')) and bool(origin.get('host_override_accepted')) and not bool(origin.get('host_override_trusted')):
        failures.append(f'{ref}: untrusted Host/authority override influenced origin selection')
    return failures


def _dns_failures(dns: dict[str, Any]) -> list[str]:
    ref = str(dns.get('resolver_ref') or 'resolver')
    failures: list[str] = []
    if not bool(dns.get('resolver_trusted', True)):
        failures.append(f'{ref}: origin resolution used an untrusted resolver')
    if not bool(dns.get('connected_address_in_answer_set', True)):
        failures.append(f'{ref}: connected address was not present in the governed DNS answer set')
    if not bool(dns.get('binding_verified', True)):
        failures.append(f'{ref}: DNS resolution-to-connect binding was not verified')
    if bool(dns.get('answer_changed_within_request')) and not (
        bool(dns.get('revalidation_performed')) and bool(dns.get('binding_verified'))
    ):
        failures.append(f'{ref}: DNS answer changed without safe revalidation and connect binding')
    if bool(dns.get('private_address_observed')) and not bool(dns.get('private_address_allowed')):
        failures.append(f'{ref}: DNS resolution crossed into a non-authorized private address boundary')
    return failures


def evaluate_cache_origin_case(case: dict[str, Any]) -> dict[str, Any]:
    expected = bool(case.get('expected_allowed'))
    accepted = bool(case.get('server_accepted'))
    failures: list[str] = []
    if accepted != expected:
        failures.append('observed cache/origin decision does not match expected policy')

    identity = _identity(case)
    resource = _resource(case)
    if accepted and identity.get('tenant_ref') and resource.get('tenant_ref') and identity.get('tenant_ref') != resource.get('tenant_ref'):
        failures.append('cross-tenant cache/origin use was accepted')

    caches = [item for item in (case.get('caches') or []) if isinstance(item, dict)]
    proxies = [item for item in (case.get('proxy_hops') or []) if isinstance(item, dict)]
    dns_items = [item for item in (case.get('dns') or []) if isinstance(item, dict)]
    origin = case.get('origin') if isinstance(case.get('origin'), dict) else {}

    for item in caches:
        failures.extend(_cache_failures(item))
    for item in proxies:
        failures.extend(_proxy_failures(item))
    failures.extend(_origin_failures(origin))
    for item in dns_items:
        failures.extend(_dns_failures(item))

    semantic = {
        'endpoint_sha256': canonical_digest(str(case.get('endpoint') or '')),
        'cache_observations': [{
            'ref': str(item.get('ref') or ''),
            'shared': bool(item.get('shared')),
            'cache_hit': bool(item.get('cache_hit')),
            'authenticated_response': bool(item.get('authenticated_response')),
            'required_key_dimensions': sorted({str(v) for v in (item.get('required_key_dimensions') or [])}),
            'observed_key_dimensions': sorted({str(v) for v in (item.get('observed_key_dimensions') or [])}),
            'cache_key_sha256': str(item.get('cache_key_sha256') or ''),
            'partition_sha256': str(item.get('partition_sha256') or ''),
        } for item in caches],
        'proxy_trust': [{
            'ref': str(item.get('ref') or ''),
            'source_trusted': bool(item.get('source_trusted')),
            'forwarded_headers_accepted': bool(item.get('forwarded_headers_accepted')),
            'forwarded_chain_valid': bool(item.get('forwarded_chain_valid', True)),
        } for item in proxies],
        'origin': {
            'ref': str(origin.get('ref') or ''),
            'expected_origin_ref': str(origin.get('expected_origin_ref') or ''),
            'selected_origin_ref': str(origin.get('selected_origin_ref') or ''),
            'authority_matches_request': bool(origin.get('authority_matches_request', True)),
        },
        'dns': [{
            'resolver_ref': str(item.get('resolver_ref') or ''),
            'resolver_trusted': bool(item.get('resolver_trusted', True)),
            'query_name_sha256': str(item.get('query_name_sha256') or ''),
            'answer_set_sha256': str(item.get('answer_set_sha256') or ''),
            'connected_address_sha256': str(item.get('connected_address_sha256') or ''),
            'connected_address_in_answer_set': bool(item.get('connected_address_in_answer_set', True)),
            'answer_changed_within_request': bool(item.get('answer_changed_within_request')),
            'binding_verified': bool(item.get('binding_verified', True)),
        } for item in dns_items],
        'failures': failures,
    }
    return {
        'passed': not failures,
        'expected_allowed': expected,
        'observed_decision': _decision(accepted),
        'semantic': semantic,
        'evidence_fingerprint': canonical_digest(semantic),
        'reason': '; '.join(failures) if failures else 'Cache, trusted proxy, origin and DNS invariants satisfied',
    }


def _project_graph(project, case: dict[str, Any], result: dict[str, Any]) -> None:
    identity = _identity(case)
    resource = _resource(case)
    identity_ref = str(identity.get('ref') or '')
    resource_ref = str(resource.get('ref') or '')
    endpoint = str(case.get('endpoint') or '')
    endpoint_ref = f'cache-origin-endpoint:{canonical_digest(endpoint)[:32]}'
    evidence = [result['evidence_fingerprint']]
    provenance = {'source': 'cache_origin_security'}
    nodes = [
        {'plane': 'identity', 'kind': 'identity', 'external_ref': f'identity:{identity_ref}', 'label': identity_ref, 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'identity_type': identity.get('type'), 'role': identity.get('role')}, 'provenance': provenance},
        {'plane': 'application', 'kind': 'resource', 'external_ref': f'resource:{resource_ref}', 'label': resource_ref, 'protocol': 'http', 'tenant_ref': str(resource.get('tenant_ref') or ''), 'properties': {'resource_type': resource.get('type')}, 'provenance': provenance},
        {'plane': 'application', 'kind': 'endpoint', 'external_ref': endpoint_ref, 'label': endpoint, 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'last_validation_passed': result['passed'], 'evidence_fingerprint': result['evidence_fingerprint']}, 'provenance': provenance},
    ]
    edges = [
        {'source_ref': f'identity:{identity_ref}', 'target_ref': endpoint_ref, 'relation': 'invokes', 'properties': {'case_ref': case.get('ref')}, 'evidence_refs': evidence, 'provenance': provenance},
        {'source_ref': endpoint_ref, 'target_ref': f'resource:{resource_ref}', 'relation': 'operates_on', 'properties': {}, 'evidence_refs': evidence, 'provenance': provenance},
    ]

    previous = endpoint_ref
    for index, cache in enumerate(case.get('caches') or []):
        ref = f'cache:{canonical_digest([case.get("ref"), index, cache.get("ref")])[:32]}'
        nodes.append({'plane': 'application', 'kind': 'cache', 'external_ref': ref, 'label': str(cache.get('ref') or 'cache'), 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'shared': bool(cache.get('shared')), 'cache_hit': bool(cache.get('cache_hit'))}, 'provenance': provenance})
        edges.append({'source_ref': previous, 'target_ref': ref, 'relation': 'caches_at', 'properties': {'index': index}, 'evidence_refs': evidence, 'provenance': provenance})
        previous = ref

    for index, proxy in enumerate(case.get('proxy_hops') or []):
        ref = f'reverse-proxy:{canonical_digest([case.get("ref"), index, proxy.get("ref")])[:32]}'
        nodes.append({'plane': 'application', 'kind': 'reverse_proxy', 'external_ref': ref, 'label': str(proxy.get('ref') or 'proxy'), 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'source_trusted': bool(proxy.get('source_trusted'))}, 'provenance': provenance})
        edges.append({'source_ref': previous, 'target_ref': ref, 'relation': 'forwards_to', 'properties': {'index': index}, 'evidence_refs': evidence, 'provenance': provenance})
        previous = ref

    origin = case.get('origin') or {}
    origin_ref = f'origin-service:{canonical_digest(str(origin.get("selected_origin_ref") or ""))[:32]}'
    nodes.append({'plane': 'application', 'kind': 'service', 'external_ref': origin_ref, 'label': str(origin.get('selected_origin_ref') or 'origin'), 'protocol': 'http', 'tenant_ref': str(identity.get('tenant_ref') or ''), 'properties': {'expected_origin_ref': str(origin.get('expected_origin_ref') or '')}, 'provenance': provenance})
    edges.append({'source_ref': previous, 'target_ref': origin_ref, 'relation': 'routes_to', 'properties': {}, 'evidence_refs': evidence, 'provenance': provenance})

    for index, dns in enumerate(case.get('dns') or []):
        resolver_ref = f'resolver:{canonical_digest(str(dns.get("resolver_ref") or ""))[:32]}'
        boundary_ref = f'dns-boundary:{canonical_digest([case.get("ref"), index, dns.get("resolver_ref")])[:32]}'
        nodes.extend([
            {'plane': 'attack_surface', 'kind': 'external_service', 'external_ref': resolver_ref, 'label': str(dns.get('resolver_ref') or 'resolver'), 'protocol': 'dns', 'tenant_ref': '', 'properties': {'trusted': bool(dns.get('resolver_trusted', True))}, 'provenance': provenance},
            {'plane': 'attack_surface', 'kind': 'trust_boundary', 'external_ref': boundary_ref, 'label': 'DNS resolution/connect boundary', 'protocol': 'dns', 'tenant_ref': '', 'properties': {'binding_verified': bool(dns.get('binding_verified', True))}, 'provenance': provenance},
        ])
        edges.extend([
            {'source_ref': origin_ref, 'target_ref': resolver_ref, 'relation': 'resolves_via', 'properties': {'index': index}, 'evidence_refs': evidence, 'provenance': provenance},
            {'source_ref': resolver_ref, 'target_ref': boundary_ref, 'relation': 'crosses_trust_boundary', 'properties': {}, 'evidence_refs': evidence, 'provenance': provenance},
        ])

    upsert_graph_snapshot(project, nodes, edges)


def run_cache_origin_security(project, actor_id: str, cases: list[dict[str, Any]], governance: dict[str, Any] | None = None):
    results = [evaluate_cache_origin_case(case) for case in cases]
    summary: dict[str, Any] = {
        'total': len(results),
        'passed': sum(1 for result in results if result['passed']),
        'failed': sum(1 for result in results if not result['passed']),
    }
    if governance:
        summary['governance'] = {
            'allowed': bool(governance.get('allowed')),
            'credential_bindings': governance.get('credential_bindings', []),
        }
    with transaction.atomic():
        run = WebSecurityValidationRun.objects.create(
            project=project,
            kind=WebSecurityValidationRun.Kind.CACHE_ORIGIN_SECURITY,
            status=WebSecurityValidationRun.Status.COMPLETED,
            contract_version=CONTRACT_VERSION,
            input_sha256=canonical_digest(cases),
            summary=summary,
            created_by_id=actor_id,
        )
        observations = []
        for case, result in zip(cases, results, strict=True):
            identity, resource = _identity(case), _resource(case)
            row = WebSecurityObservation.objects.create(
                run=run,
                case_ref=str(case.get('ref') or ''),
                identity_ref=str(identity.get('ref') or ''),
                identity_type=str(identity.get('type') or ''),
                role=str(identity.get('role') or ''),
                tenant_ref=str(identity.get('tenant_ref') or ''),
                resource_ref=str(resource.get('ref') or ''),
                resource_tenant_ref=str(resource.get('tenant_ref') or ''),
                endpoint=str(case.get('endpoint') or ''),
                method=str(case.get('method') or ''),
                operation=str(case.get('operation') or 'request'),
                expected_allowed=result['expected_allowed'],
                observed_decision=result['observed_decision'],
                passed=result['passed'],
                semantic=result['semantic'],
                evidence_fingerprint=result['evidence_fingerprint'],
                reason=result['reason'],
            )
            observations.append(row)
            _project_graph(project, case, result)
    return run, observations
