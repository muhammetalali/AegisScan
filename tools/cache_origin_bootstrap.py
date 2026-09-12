from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding='utf-8')
    if old not in text:
        raise SystemExit(f'anchor not found in {path}: {old!r}')
    if text.count(old) != 1:
        raise SystemExit(f'anchor is not unique in {path}: {old!r}')
    target.write_text(text.replace(old, new, 1), encoding='utf-8')


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content.rstrip() + '\n', encoding='utf-8')


replace_once(
    'aegis-platform/backend/enterprise/web_security_models.py',
    "        HTTP_PROTOCOL_SECURITY = 'http_protocol_security', 'HTTP Protocol Security'\n",
    "        HTTP_PROTOCOL_SECURITY = 'http_protocol_security', 'HTTP Protocol Security'\n        CACHE_ORIGIN_SECURITY = 'cache_origin_security', 'Cache Origin Security'\n",
)

replace_once(
    'aegis-platform/backend/fastapi_app/services/credential_execution.py',
    "    'http-protocol.security-validation',\n}",
    "    'http-protocol.security-validation',\n    'cache-origin.security-validation',\n}",
)

replace_once(
    'aegis-platform/backend/fastapi_app/routers/web_security.py',
    'from fastapi_app.contracts.http_protocol_security import HttpProtocolBatchIn\n',
    'from fastapi_app.contracts.http_protocol_security import HttpProtocolBatchIn\nfrom fastapi_app.contracts.cache_origin_security import CacheOriginBatchIn\n',
)
replace_once(
    'aegis-platform/backend/fastapi_app/routers/web_security.py',
    'from fastapi_app.services.http_protocol_security import run_http_protocol_security\n',
    'from fastapi_app.services.http_protocol_security import run_http_protocol_security\nfrom fastapi_app.services.cache_origin_security import run_cache_origin_security\n',
)
replace_once(
    'aegis-platform/backend/fastapi_app/routers/web_security.py',
    "            'identity_protocol_security': True,\n",
    "            'identity_protocol_security': True,\n            'http_protocol_security': True,\n            'cache_origin_security': True,\n",
)

router = ROOT / 'aegis-platform/backend/fastapi_app/routers/web_security.py'
router_text = router.read_text(encoding='utf-8').rstrip()
route_marker = "@router.post('/projects/{project_id}/cache-origin/evaluate')"
if route_marker in router_text:
    raise SystemExit('cache-origin route already present')
router_text += r'''


@router.post('/projects/{project_id}/cache-origin/evaluate')
async def evaluate_cache_origin_security(
    project_id: str,
    payload: CacheOriginBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project, payload.budget_id, capability='cache_origin_security', cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project, uid, capability_id='cache-origin.security-validation',
        target_origin=payload.target_origin, cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_cache_origin_security)(project, uid, cases, governance)
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }
'''
router.write_text(router_text.rstrip() + '\n', encoding='utf-8')

write('aegis-platform/backend/fastapi_app/contracts/cache_origin_security.py', r'''
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from fastapi_app.contracts.web_security_v2 import IdentityIn, ResourceIn


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


CacheDimension = Literal[
    'scheme', 'host', 'path', 'query', 'authorization', 'cookie', 'tenant', 'identity'
]


class CacheObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    shared: bool
    cache_hit: bool
    authenticated_response: bool = False
    response_private: bool = False
    response_no_store: bool = False
    required_key_dimensions: list[CacheDimension] = Field(default_factory=list, max_length=16)
    observed_key_dimensions: list[CacheDimension] = Field(default_factory=list, max_length=16)
    cache_key_sha256: str = Field(default='', max_length=64)
    partition_sha256: str = Field(default='', max_length=64)


class ProxyTrustObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    source_trusted: bool
    forwarded_headers_present: bool = False
    forwarded_headers_accepted: bool = False
    forwarded_chain_valid: bool = True
    host_selected_from_forwarded: bool = False
    scheme_selected_from_forwarded: bool = False
    client_identity_selected_from_forwarded: bool = False


class OriginObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    expected_origin_ref: str = Field(min_length=1, max_length=255)
    selected_origin_ref: str = Field(min_length=1, max_length=255)
    authority_matches_request: bool = True
    host_override_present: bool = False
    host_override_trusted: bool = False
    host_override_accepted: bool = False


class DNSObservationIn(StrictModel):
    resolver_ref: str = Field(min_length=1, max_length=255)
    resolver_trusted: bool = True
    query_name_sha256: str = Field(min_length=64, max_length=64)
    answer_set_sha256: str = Field(min_length=64, max_length=64)
    connected_address_sha256: str = Field(min_length=64, max_length=64)
    connected_address_in_answer_set: bool = True
    answer_changed_within_request: bool = False
    revalidation_performed: bool = True
    binding_verified: bool = True
    private_address_observed: bool = False
    private_address_allowed: bool = False
    ttl_seconds: int | None = Field(default=None, ge=0, le=604800)


class CacheOriginCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    endpoint: str = Field(min_length=1, max_length=700)
    method: str = Field(min_length=1, max_length=32)
    operation: str = Field(default='request', max_length=160)
    expected_allowed: bool
    server_accepted: bool
    caches: list[CacheObservationIn] = Field(default_factory=list, max_length=8)
    proxy_hops: list[ProxyTrustObservationIn] = Field(default_factory=list, max_length=8)
    origin: OriginObservationIn
    dns: list[DNSObservationIn] = Field(default_factory=list, max_length=8)


class CacheOriginBatchIn(StrictModel):
    budget_id: UUID
    target_origin: str = Field(min_length=1, max_length=700)
    cases: list[CacheOriginCaseIn] = Field(min_length=1, max_length=5000)
''')

write('aegis-platform/backend/fastapi_app/services/cache_origin_security.py', r'''
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
''')

write('aegis-platform/backend/fastapi_app/services/test_cache_origin_security.py', r'''
from __future__ import annotations

import json
import uuid

import pytest
from pydantic import ValidationError

from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.contracts.cache_origin_security import CacheOriginCaseIn
from fastapi_app.services.cache_origin_security import evaluate_cache_origin_case, run_cache_origin_security


H = 'a' * 64
H2 = 'b' * 64
H3 = 'c' * 64


def _identity(tenant='tenant-a'):
    return {'ref': 'alice', 'type': 'user', 'role': 'viewer', 'tenant_ref': tenant, 'scopes': [], 'credential_ref': ''}


def _resource(tenant='tenant-a'):
    return {'ref': 'record-a', 'type': 'record', 'tenant_ref': tenant, 'owner_ref': 'alice'}


def _case(**overrides):
    base = {
        'ref': 'cache-safe',
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': '/records',
        'method': 'GET',
        'operation': 'read',
        'expected_allowed': True,
        'server_accepted': True,
        'caches': [{
            'ref': 'edge-cache', 'shared': True, 'cache_hit': True, 'authenticated_response': True,
            'response_private': False, 'response_no_store': False,
            'required_key_dimensions': ['host', 'path', 'tenant'],
            'observed_key_dimensions': ['host', 'path', 'tenant'],
            'cache_key_sha256': H, 'partition_sha256': H2,
        }],
        'proxy_hops': [{
            'ref': 'edge', 'source_trusted': True, 'forwarded_headers_present': True,
            'forwarded_headers_accepted': True, 'forwarded_chain_valid': True,
            'host_selected_from_forwarded': True, 'scheme_selected_from_forwarded': True,
            'client_identity_selected_from_forwarded': False,
        }],
        'origin': {
            'ref': 'origin-route', 'expected_origin_ref': 'origin-a', 'selected_origin_ref': 'origin-a',
            'authority_matches_request': True, 'host_override_present': False,
            'host_override_trusted': False, 'host_override_accepted': False,
        },
        'dns': [{
            'resolver_ref': 'resolver-a', 'resolver_trusted': True,
            'query_name_sha256': H, 'answer_set_sha256': H2, 'connected_address_sha256': H3,
            'connected_address_in_answer_set': True, 'answer_changed_within_request': False,
            'revalidation_performed': True, 'binding_verified': True,
            'private_address_observed': False, 'private_address_allowed': False, 'ttl_seconds': 60,
        }],
    }
    base.update(overrides)
    return base


def test_contract_forbids_raw_secret_and_payload_fields():
    for forbidden in ('raw_body', 'authorization', 'cookie', 'raw_headers'):
        payload = _case()
        payload[forbidden] = 'must-never-enter-evidence'
        with pytest.raises(ValidationError):
            CacheOriginCaseIn.model_validate(payload)


def test_cache_origin_detects_cache_proxy_origin_and_dns_boundary_failures():
    case = _case(
        ref='cache-danger',
        caches=[{
            'ref': 'shared', 'shared': True, 'cache_hit': True, 'authenticated_response': True,
            'response_private': True, 'response_no_store': True,
            'required_key_dimensions': ['host', 'path', 'tenant', 'identity'],
            'observed_key_dimensions': ['host', 'path'], 'cache_key_sha256': H, 'partition_sha256': H2,
        }],
        proxy_hops=[{
            'ref': 'internet-edge', 'source_trusted': False, 'forwarded_headers_present': True,
            'forwarded_headers_accepted': True, 'forwarded_chain_valid': False,
            'host_selected_from_forwarded': True, 'scheme_selected_from_forwarded': False,
            'client_identity_selected_from_forwarded': True,
        }],
        origin={
            'ref': 'origin-route', 'expected_origin_ref': 'origin-a', 'selected_origin_ref': 'origin-b',
            'authority_matches_request': False, 'host_override_present': True,
            'host_override_trusted': False, 'host_override_accepted': True,
        },
        dns=[{
            'resolver_ref': 'resolver-x', 'resolver_trusted': False,
            'query_name_sha256': H, 'answer_set_sha256': H2, 'connected_address_sha256': H3,
            'connected_address_in_answer_set': False, 'answer_changed_within_request': True,
            'revalidation_performed': False, 'binding_verified': False,
            'private_address_observed': True, 'private_address_allowed': False, 'ttl_seconds': 0,
        }],
    )
    result = evaluate_cache_origin_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in (
        'cache key omits required dimensions', 'shared cache served a response marked private',
        'shared cache served a response marked no-store', 'untrusted source were accepted',
        'invalid forwarded chain', 'selected from an untrusted forwarded header',
        'selected origin does not match', 'authority does not match', 'Host/authority override',
        'untrusted resolver', 'not present in the governed DNS answer set',
        'binding was not verified', 'changed without safe revalidation', 'private address boundary',
    ):
        assert marker in joined
    semantic = json.dumps(result['semantic'], sort_keys=True)
    assert '/records' not in semantic
    assert 'must-never-enter-evidence' not in semantic


def test_cache_origin_accepts_governed_cache_proxy_origin_and_dns_path():
    result = evaluate_cache_origin_case(_case())
    assert result['passed'] is True
    assert len(result['evidence_fingerprint']) == 64


def test_cache_origin_rejects_cross_tenant_acceptance():
    result = evaluate_cache_origin_case(_case(resource=_resource('tenant-b')))
    assert result['passed'] is False
    assert 'cross-tenant' in result['reason']


@pytest.mark.django_db
def test_cache_origin_persists_immutable_evidence_and_security_graph():
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(email=f'cache-{suffix}@example.test', password='Cache-Test-Only-Password!42')
    project = Project.objects.create(name=f'Cache {suffix}', slug=f'cache-{suffix}', owner=user)
    run, observations = run_cache_origin_security(
        project, str(user.id), [_case()], {'allowed': True, 'credential_bindings': []},
    )
    assert run.summary['passed'] == 1
    assert observations[0].passed is True
    assert '/records' not in json.dumps(observations[0].semantic)
    kinds = set(project.security_graph_nodes.values_list('kind', flat=True))
    assert {'identity', 'resource', 'endpoint', 'cache', 'reverse_proxy', 'service', 'external_service', 'trust_boundary'}.issubset(kinds)
    relations = set(project.security_graph_edges.values_list('relation', flat=True))
    assert {'invokes', 'operates_on', 'caches_at', 'forwards_to', 'routes_to', 'resolves_via', 'crosses_trust_boundary'}.issubset(relations)
    with pytest.raises(RuntimeError, match='immutable'):
        type(observations[0]).objects.filter(pk=observations[0].pk).update(passed=False)
''')

write('aegis-platform/backend/fastapi_app/services/test_cache_origin_credential_scope.py', r'''
from __future__ import annotations

import uuid

import pytest
from django.contrib.auth import get_user_model

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution

CAPABILITY = 'cache-origin.security-validation'
ORIGIN = 'https://cache-fixture.example'
IDENTITY = 'alice'


def _fixture():
    suffix = uuid.uuid4().hex[:10]
    user = get_user_model().objects.create_user(email=f'cache-vault-{suffix}@example.test', password='Cache-Vault-Test-Only-123!')
    project = Project.objects.create(name=f'Cache Vault {suffix}', slug=f'cache-vault-{suffix}', owner=user)
    credential = create_credential_secret(
        project=project, actor=user, name='cache-origin-token', kind=CredentialSecret.Kind.TOKEN,
        secret='cache-origin-secret-material',
        scope={'protocol_origin': ORIGIN, 'protocol_identity_ref': IDENTITY},
    )
    return user, project, credential


@pytest.mark.django_db
def test_cache_origin_capability_enforces_origin_and_identity_binding():
    user, project, credential = _fixture()
    context = authorize_credential_refs_for_execution(
        project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
        capability_id=CAPABILITY, allowed_kinds=('token', 'api_key', 'generic'),
        purpose='cache-origin:test', target=ORIGIN, identity_ref=IDENTITY,
    )
    assert context['credential_material_handling'] == 'reference-authorized-only'
    assert context['credential_refs'][0]['protocol_identity_ref'] == IDENTITY
    assert 'cache-origin-secret-material' not in str(context)


@pytest.mark.django_db
@pytest.mark.parametrize(('target', 'identity_ref'), [('https://other.example', IDENTITY), (ORIGIN, 'mallory')])
def test_cache_origin_capability_denies_scope_or_identity_mismatch(target, identity_ref):
    user, project, credential = _fixture()
    with pytest.raises(CredentialVaultDenied, match='not scoped'):
        authorize_credential_refs_for_execution(
            project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
            capability_id=CAPABILITY, allowed_kinds=('token', 'api_key', 'generic'),
            purpose='cache-origin:test-deny', target=target, identity_ref=identity_ref,
        )
    denied = CredentialAccess.objects.filter(
        credential=credential, result=CredentialAccess.Result.DENIED,
    ).latest('created_at')
    assert denied.metadata['scope_type'] == 'protocol_origin+identity'
    assert denied.metadata['scope_matches_target'] is (target == ORIGIN)
    assert denied.metadata['identity_binding_matches'] is (identity_ref == IDENTITY)
''')

write('aegis-platform/backend/enterprise/migrations/0021_cache_origin_security_validation_kind.py', r'''
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('enterprise', '0020_http_protocol_security_validation_kind')]

    operations = [
        migrations.AlterField(
            model_name='websecurityvalidationrun',
            name='kind',
            field=models.CharField(
                max_length=40,
                choices=[
                    ('authorization_matrix', 'Authorization Matrix'),
                    ('negative_path', 'Negative Path'),
                    ('response_comparison', 'Response Comparison'),
                    ('websocket_security', 'WebSocket Security'),
                    ('graphql_security', 'GraphQL Security'),
                    ('cross_protocol', 'Cross-Protocol State'),
                    ('identity_protocol_security', 'Identity Protocol Security'),
                    ('http_protocol_security', 'HTTP Protocol Security'),
                    ('cache_origin_security', 'Cache Origin Security'),
                ],
            ),
        ),
    ]
''')

write('.github/workflows/cache-origin-security-reality.yml', r'''
name: Cache Origin Security Reality

on:
  pull_request:
    branches: [main]
    paths:
      - 'aegis-platform/backend/enterprise/**'
      - 'aegis-platform/backend/fastapi_app/contracts/cache_origin_security.py'
      - 'aegis-platform/backend/fastapi_app/routers/web_security.py'
      - 'aegis-platform/backend/fastapi_app/services/cache_origin_security.py'
      - 'aegis-platform/backend/fastapi_app/services/credential_execution.py'
      - 'aegis-platform/backend/fastapi_app/services/test_cache_origin_*.py'
      - '.github/workflows/cache-origin-security-reality.yml'
  push:
    branches: [main, codex/cache-origin-dns-security-2026-09-12]
    paths:
      - 'aegis-platform/backend/enterprise/**'
      - 'aegis-platform/backend/fastapi_app/contracts/cache_origin_security.py'
      - 'aegis-platform/backend/fastapi_app/routers/web_security.py'
      - 'aegis-platform/backend/fastapi_app/services/cache_origin_security.py'
      - 'aegis-platform/backend/fastapi_app/services/credential_execution.py'
      - 'aegis-platform/backend/fastapi_app/services/test_cache_origin_*.py'
      - '.github/workflows/cache-origin-security-reality.yml'
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: cache-origin-security-${{ github.event_name == 'pull_request' && format('pr-{0}', github.event.pull_request.number) || github.ref }}
  cancel-in-progress: true

jobs:
  cache-origin-security:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    env:
      DEBUG: 'False'
      SECRET_KEY: ci-cache-origin-django-secret-key-0123456789abcdef0123456789
      JWT_SECRET_KEY: ci-cache-origin-jwt-secret-key-0123456789abcdef0123456789
      DATABASE_URL: postgresql://aegis:aegis@127.0.0.1:5432/aegis
      REDIS_URL: redis://127.0.0.1:6379/0
      CELERY_BROKER_URL: redis://127.0.0.1:6379/0
      CELERY_RESULT_BACKEND: redis://127.0.0.1:6379/0
      ALLOWED_HOSTS: localhost,127.0.0.1
      CORS_ALLOWED_ORIGINS: http://localhost:5173
      AEGIS_EVIDENCE_HMAC_KEY: ci-cache-origin-evidence-hmac-key-0123456789
      CREDENTIAL_VAULT_KEYS: Gda3DhfD-EcoacpdQeTFnHHH1Q_rxQZaUISBiMvSwUM=
      CREDENTIAL_FINGERPRINT_KEY: ci-cache-origin-credential-fingerprint-key-0123456789

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_DB: aegis
          POSTGRES_USER: aegis
          POSTGRES_PASSWORD: aegis
        ports: ['5432:5432']
        options: >-
          --health-cmd "pg_isready -U aegis -d aegis"
          --health-interval 10s --health-timeout 5s --health-retries 10
      redis:
        image: redis:7
        ports: ['6379:6379']
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s --health-timeout 5s --health-retries 10

    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: '3.12'
          cache: pip
          cache-dependency-path: aegis-platform/backend/requirements.txt
      - name: Install backend dependencies
        run: python -m pip install -r aegis-platform/backend/requirements.txt
      - name: Compile cache origin security plane
        run: |
          python -m py_compile \
            aegis-platform/backend/enterprise/web_security_models.py \
            aegis-platform/backend/fastapi_app/contracts/cache_origin_security.py \
            aegis-platform/backend/fastapi_app/services/cache_origin_security.py \
            aegis-platform/backend/fastapi_app/services/credential_execution.py \
            aegis-platform/backend/fastapi_app/services/test_cache_origin_security.py \
            aegis-platform/backend/fastapi_app/services/test_cache_origin_credential_scope.py \
            aegis-platform/backend/fastapi_app/routers/web_security.py
      - name: Django model and migration reality
        working-directory: aegis-platform/backend
        env:
          DJANGO_SETTINGS_MODULE: django_project.settings
          PYTHONPATH: ${{ github.workspace }}/aegis-platform/backend
        run: |
          python manage.py check
          python manage.py makemigrations --check --dry-run
          python manage.py migrate --noinput
      - name: Cache DNS origin trusted proxy Vault and persistence suite
        working-directory: aegis-platform/backend
        env:
          DJANGO_SETTINGS_MODULE: django_project.settings
          PYTHONPATH: ${{ github.workspace }}/aegis-platform/backend
        run: |
          pytest -q \
            fastapi_app/services/test_cache_origin_security.py \
            fastapi_app/services/test_cache_origin_credential_scope.py \
            --junitxml=/tmp/cache-origin-security-junit.xml
      - name: Verify API registration and secret-safe contract
        working-directory: aegis-platform/backend
        env:
          DJANGO_SETTINGS_MODULE: django_project.settings
          PYTHONPATH: ${{ github.workspace }}/aegis-platform/backend
        run: |
          python - <<'PY'
          from fastapi_app.main import app
          from fastapi_app.contracts.cache_origin_security import CacheOriginCaseIn, CacheObservationIn, DNSObservationIn

          paths = app.openapi()['paths']
          route = '/api/v1/web-security/projects/{project_id}/cache-origin/evaluate'
          assert route in paths, sorted(p for p in paths if 'cache' in p or 'origin' in p)
          forbidden = {'raw_body', 'raw_headers', 'authorization', 'cookie', 'set_cookie', 'request_bytes', 'response_bytes', 'credential', 'secret'}
          assert forbidden.isdisjoint(CacheOriginCaseIn.model_fields)
          assert forbidden.isdisjoint(CacheObservationIn.model_fields)
          assert forbidden.isdisjoint(DNSObservationIn.model_fields)
          print('CACHE_ORIGIN_API_REGISTRATION=PASS')
          print('CACHE_ORIGIN_SECRET_SAFE_CONTRACT=PASS')
          PY
      - name: Retain cache origin evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: cache-origin-security-reality-${{ github.sha }}
          path: /tmp/cache-origin-security-junit.xml
          retention-days: 30
          if-no-files-found: warn
''')

print('CACHE_ORIGIN_BOOTSTRAP=READY')
