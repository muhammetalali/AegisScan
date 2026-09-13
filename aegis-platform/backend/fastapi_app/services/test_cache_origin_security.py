
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
