from __future__ import annotations

import json
import uuid

import pytest
from pydantic import ValidationError

from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.contracts.http_protocol_security import HttpProtocolCaseIn
from fastapi_app.services.http_protocol_security import evaluate_http_protocol_case, run_http_protocol_security


def _identity():
    return {'ref': 'alice', 'type': 'user', 'role': 'viewer', 'tenant_ref': 'tenant-a', 'scopes': [], 'credential_ref': ''}


def _resource():
    return {'ref': 'record-a', 'type': 'record', 'tenant_ref': 'tenant-a', 'owner_ref': 'alice'}


def _hop(ref, role, protocol='http/1.1', **overrides):
    base = {
        'ref': ref, 'role': role, 'protocol': protocol, 'method': 'POST', 'path': '/records',
        'authority': 'app.example', 'host': 'app.example', 'content_length_values': [4],
        'body_length_bytes': 4, 'semantic_body_sha256': 'a' * 64, 'transfer_encodings': [],
        'te_header_values': [], 'connection_tokens': [], 'pseudo_headers_valid': True,
        'pseudo_headers_order_valid': True, 'message_complete': True, 'parser_accepted': True,
        'framing_boundary_ref': 'boundary-a', 'trailer_declared': [], 'trailer_observed': [],
    }
    base.update(overrides)
    return base


def _case(**overrides):
    base = {
        'ref': 'http-fixed', 'identity': _identity(), 'resource': _resource(), 'endpoint': '/records',
        'method': 'POST', 'operation': 'write', 'expected_allowed': True, 'server_accepted': True,
        'hops': [_hop('edge', 'edge'), _hop('origin', 'origin', 'h2')],
        'response': {'protocol': 'h2', 'status_code': 200, 'content_length_values': [2], 'body_length_bytes': 2,
                     'connection_tokens': [], 'transfer_encodings': [], 'te_header_values': [],
                     'trailer_declared': [], 'trailer_observed': []},
    }
    base.update(overrides)
    return base


def test_contract_rejects_raw_payload_fields():
    payload = _case()
    payload['raw_body'] = 'must-never-enter-evidence'
    with pytest.raises(ValidationError):
        HttpProtocolCaseIn.model_validate(payload)


def test_http_protocol_consistency_detects_desync_and_translation_drift():
    case = _case(
        ref='http-vulnerable', expected_allowed=False, server_accepted=True,
        hops=[
            _hop('edge', 'edge', content_length_values=[4, 7], transfer_encodings=['chunked']),
            _hop('gateway', 'gateway', 'h2', path='/admin', authority='other.example', host='app.example',
                 semantic_body_sha256='b' * 64, connection_tokens=['keep-alive'], pseudo_headers_order_valid=False),
        ],
        response={'protocol': 'h2', 'status_code': 200, 'content_length_values': [10], 'body_length_bytes': 2,
                  'connection_tokens': ['keep-alive'], 'transfer_encodings': [], 'te_header_values': ['gzip'],
                  'trailer_declared': [], 'trailer_observed': ['x-proof']},
    )
    result = evaluate_http_protocol_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in ('conflicting Content-Length', 'Transfer-Encoding and Content-Length', 'path semantics changed',
                   'authority and Host disagree', 'authority semantics changed', 'semantic body changed',
                   'connection-specific headers', 'pseudo-header ordering', 'Content-Length does not match',
                   'TE value is not trailers', 'undeclared trailers'):
        assert marker in joined
    persisted = json.dumps(result['semantic'], sort_keys=True)
    assert 'raw_body' not in persisted
    assert '/records' not in persisted


def test_http_protocol_consistency_accepts_safe_h1_to_h2_translation():
    result = evaluate_http_protocol_case(_case())
    assert result['passed'] is True
    assert result['semantic']['protocol_chain'] == ['http/1.1', 'h2']
    assert len(result['evidence_fingerprint']) == 64


@pytest.mark.django_db
def test_http_protocol_run_persists_immutable_evidence_and_graph():
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(email=f'http-{suffix}@example.test', password='Http-Test-Only-Password!42')
    project = Project.objects.create(name=f'HTTP {suffix}', slug=f'http-{suffix}', owner=user)
    run, observations = run_http_protocol_security(project, str(user.id), [_case()], {'allowed': True, 'credential_bindings': []})
    assert run.summary['passed'] == 1
    assert observations[0].passed is True
    assert observations[0].semantic['hops'][0]['path_sha256']
    assert '/records' not in json.dumps(observations[0].semantic)
    kinds = set(project.security_graph_nodes.values_list('kind', flat=True))
    assert {'identity', 'resource', 'endpoint', 'reverse_proxy', 'service'}.issubset(kinds)
    relations = set(project.security_graph_edges.values_list('relation', flat=True))
    assert {'invokes', 'operates_on', 'forwards_to'}.issubset(relations)
    with pytest.raises(RuntimeError, match='immutable'):
        type(observations[0]).objects.filter(pk=observations[0].pk).update(passed=False)
