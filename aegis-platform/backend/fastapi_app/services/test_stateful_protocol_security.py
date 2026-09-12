from __future__ import annotations

import json
import uuid

import pytest

from django_project.projects.models import Project
from django_project.users.models import User
from fastapi_app.services.web_security_foundation import persist_policy, run_authorization_matrix
from fastapi_app.services.stateful_protocol_security import (
    evaluate_cross_protocol_case,
    evaluate_graphql_case,
    evaluate_websocket_case,
    graphql_schema_inventory,
    run_cross_protocol_security,
    run_graphql_security,
    run_websocket_security,
)


def _user_project(prefix: str):
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f'{prefix}-{suffix}@example.com',
        password='Protocol-Test-Only-Password!42',
        first_name='Protocol',
        last_name='Fixture',
    )
    project = Project.objects.create(
        name=f'{prefix}-{suffix}',
        slug=f'{prefix}-{suffix}',
        owner=user,
        environment=Project.Environment.STAGING,
    )
    return user, project


def _identity():
    return {
        'ref': 'alice',
        'type': 'user',
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'scopes': ['records:read'],
    }


def _resource(tenant='tenant-a', owner='alice', ref='record-a'):
    return {
        'ref': ref,
        'type': 'record',
        'tenant_ref': tenant,
        'owner_ref': owner,
    }


def test_websocket_security_detects_csws_hijack_cross_tenant_and_session_reuse():
    case = {
        'ref': 'ws-vulnerable',
        'identity': _identity(),
        'resource': _resource('tenant-b', 'bob', 'record-b'),
        'channel': 'ws://fixture/ws/tenant-b/record-b',
        'origin': 'https://evil.example',
        'allowed_origins': ['https://app.example'],
        'authentication_required': True,
        'authenticated': False,
        'session_state': 'expired',
        'requested_action': 'subscribe',
        'expected_allowed': False,
        'server_accepted': True,
        'handshake_status': 101,
        'subscription_owner_ref': 'bob',
        'subscription_tenant_ref': 'tenant-b',
        'reconnect': True,
        'reconnect_reauthenticated': False,
        'message_schema_valid': False,
        'message_authorized': False,
        'binary': True,
        'binary_allowed': False,
        'message_size_bytes': 4096,
        'max_message_size_bytes': 1024,
        'observed_messages': 101,
        'rate_limit_threshold': 100,
        'rate_limited': False,
    }
    result = evaluate_websocket_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in (
        'cross-origin WebSocket handshake',
        'unauthenticated WebSocket',
        'expired WebSocket session',
        'cross-tenant WebSocket subscription',
        'ownership boundary',
        'without reauthentication',
        'schema-invalid',
        'message-level authorization',
        'binary WebSocket',
        'oversized WebSocket',
        'rate threshold',
        'does not match expected policy',
    ):
        assert marker in joined
    assert len(result['evidence_fingerprint']) == 64


def test_graphql_security_detects_bola_bfla_sensitive_introspection_and_resource_limits():
    case = {
        'ref': 'graphql-vulnerable',
        'identity': _identity(),
        'resource': _resource('tenant-b', 'bob', 'record-b'),
        'endpoint': '/graphql-vulnerable',
        'operation_type': 'mutation',
        'operation_name': 'UpdateRecord',
        'field_path': 'updateRecord.secret',
        'expected_allowed': False,
        'server_accepted': True,
        'response_status': 200,
        'errors_count': 0,
        'field_authorized': False,
        'mutation_authorized': False,
        'sensitive_fields_requested': ['secret'],
        'sensitive_fields_returned': ['secret'],
        'introspection_requested': True,
        'introspection_expected_allowed': False,
        'batch_size': 20,
        'max_batch_size': 10,
        'depth': 20,
        'max_depth': 8,
        'complexity': 5000,
        'max_complexity': 1000,
    }
    result = evaluate_graphql_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in (
        'authorization decision',
        'cross-tenant GraphQL',
        'field-level authorization',
        'unauthorized GraphQL mutation',
        'sensitive GraphQL fields',
        'GraphQL introspection',
        'batch size',
        'depth limit',
        'complexity limit',
    ):
        assert marker in joined


def test_cross_protocol_security_detects_identity_tenant_and_session_drift():
    result = evaluate_cross_protocol_case({
        'ref': 'browser-to-ws-drift',
        'identity': _identity(),
        'resource': _resource(),
        'session_ref': 'session-a',
        'from_protocol': 'browser',
        'to_protocol': 'websocket',
        'operation': 'subscribe',
        'expected_allowed': False,
        'observed_allowed': True,
        'identity_consistent': False,
        'tenant_consistent': False,
        'session_bound': False,
    })
    assert result['passed'] is False
    assert len(result['semantic']['failures']) == 4


@pytest.mark.django_db
def test_protocol_runs_persist_immutable_observations_and_security_graph():
    user, project = _user_project('protocol-persist')

    ws_run, ws_obs = run_websocket_security(project, str(user.id), [{
        'ref': 'ws-fixed-own',
        'identity': _identity(),
        'resource': _resource(),
        'channel': 'ws://fixture/ws/tenant-a/record-a',
        'session_ref': 'session-a',
        'origin': 'https://app.example',
        'allowed_origins': ['https://app.example'],
        'authentication_required': True,
        'authenticated': True,
        'session_state': 'active',
        'requested_action': 'subscribe',
        'expected_allowed': True,
        'server_accepted': True,
        'handshake_status': 101,
        'subscription_owner_ref': 'alice',
        'subscription_tenant_ref': 'tenant-a',
        'reconnect': False,
        'reconnect_reauthenticated': False,
        'message_schema_valid': True,
        'message_authorized': True,
        'binary': False,
        'binary_allowed': False,
        'message_size_bytes': 32,
        'max_message_size_bytes': 1024,
        'observed_messages': 1,
        'rate_limit_threshold': 100,
        'rate_limited': False,
    }])
    assert ws_run.summary == {'total': 1, 'passed': 1, 'failed': 0}
    assert ws_obs[0].passed is True
    assert 'session_ref' not in ws_obs[0].semantic
    assert ws_obs[0].semantic['session_ref_hmac']
    assert ws_obs[0].semantic['session_ref_hmac'] != 'session-a'

    gql_run, gql_obs = run_graphql_security(project, str(user.id), [{
        'ref': 'gql-fixed-own',
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': '/graphql',
        'session_ref': 'session-a',
        'operation_type': 'query',
        'operation_name': 'Record',
        'schema_sdl': '''
            type Record { id: ID!, owner: String! }
            type Query { record(id: ID!): Record }
        ''',
        'field_path': 'record.id',
        'expected_allowed': True,
        'server_accepted': True,
        'response_status': 200,
        'errors_count': 0,
        'field_authorized': True,
        'mutation_authorized': True,
        'sensitive_fields_requested': [],
        'sensitive_fields_returned': [],
        'introspection_requested': False,
        'introspection_expected_allowed': False,
        'batch_size': 1,
        'max_batch_size': 10,
        'depth': 2,
        'max_depth': 8,
        'complexity': 3,
        'max_complexity': 100,
    }])
    assert gql_run.summary['passed'] == 1
    assert gql_obs[0].passed is True
    assert 'session_ref' not in gql_obs[0].semantic
    assert gql_obs[0].semantic['session_ref_hmac']
    assert gql_obs[0].semantic['session_ref_hmac'] != 'session-a'

    cross_run, cross_obs = run_cross_protocol_security(project, str(user.id), [{
        'ref': 'gql-to-ws',
        'identity': _identity(),
        'resource': _resource(),
        'session_ref': 'session-a',
        'from_protocol': 'graphql',
        'to_protocol': 'websocket',
        'operation': 'subscribe',
        'expected_allowed': False,
        'observed_allowed': False,
        'identity_consistent': False,
        'tenant_consistent': False,
        'session_bound': False,
        'source_observation_id': str(gql_obs[0].id),
        'target_observation_id': str(ws_obs[0].id),
    }])
    assert cross_run.summary['failed'] == 0
    assert cross_obs[0].passed is True

    persisted_graph = json.dumps(
        list(project.security_graph_nodes.values('external_ref', 'label', 'properties')),
        sort_keys=True,
        default=str,
    )
    assert 'session-a' not in persisted_graph
    kinds = set(project.security_graph_nodes.values_list('kind', flat=True))
    assert {
        'identity', 'resource', 'websocket_channel', 'graphql_operation',
        'graphql_type', 'graphql_field', 'graphql_argument', 'session', 'channel',
    }.issubset(kinds)
    relations = set(project.security_graph_edges.values_list('relation', flat=True))
    assert {'subscribes_to', 'streams_resource', 'invokes', 'operates_on', 'transitions_to'}.issubset(relations)


    _foreign_user, foreign_project = _user_project('protocol-foreign')
    _foreign_run, foreign_ws = run_websocket_security(foreign_project, str(_foreign_user.id), [{
        'ref': 'ws-foreign',
        'identity': _identity(),
        'resource': _resource(),
        'channel': 'ws://fixture/ws/tenant-a/record-a',
        'session_ref': 'session-a',
        'origin': 'https://app.example',
        'allowed_origins': ['https://app.example'],
        'authentication_required': True,
        'authenticated': True,
        'session_state': 'active',
        'requested_action': 'subscribe',
        'expected_allowed': True,
        'server_accepted': True,
        'handshake_status': 101,
        'subscription_owner_ref': 'alice',
        'subscription_tenant_ref': 'tenant-a',
    }])
    with pytest.raises(ValueError, match='same project'):
        run_cross_protocol_security(project, str(user.id), [{
            'ref': 'forged-foreign-lineage',
            'identity': _identity(),
            'resource': _resource(),
            'session_ref': 'session-a',
            'from_protocol': 'graphql',
            'to_protocol': 'websocket',
            'operation': 'subscribe',
            'expected_allowed': True,
            'observed_allowed': True,
            'identity_consistent': True,
            'tenant_consistent': True,
            'session_bound': True,
            'source_observation_id': str(gql_obs[0].id),
            'target_observation_id': str(foreign_ws[0].id),
        }])

@pytest.mark.django_db
def test_https_to_graphql_transition_uses_persisted_identity_tenant_and_session_lineage():
    user, project = _user_project('protocol-rest-lineage')
    persist_policy(project, str(user.id), {
        'identity_type': 'user',
        'role': 'viewer',
        'tenant_ref': 'tenant-a',
        'endpoint': '/records/*',
        'method': 'GET',
        'operation': 'read',
        'resource_type': 'record',
        'allowed': True,
        'ownership_rule': 'owner_only',
        'tenant_rule': 'same_tenant',
        'sensitive_operation': False,
        'required_scopes': ['records:read'],
        'conditions': {},
        'policy_source': 'operator_declared',
        'provenance': {'source_ref': 'test://protocol-rest-lineage'},
        'confidence': 1.0,
        'version': 1,
    })
    _http_run, http_obs = run_authorization_matrix(project, str(user.id), [{
        'ref': 'rest-own',
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': '/records/record-a',
        'method': 'GET',
        'operation': 'read',
        'protocol': 'https',
        'session_ref': 'session-rest-a',
        'response': {
            'status_code': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': {'id': 'record-a', 'tenant': 'tenant-a', 'owner': 'alice'},
            'timing_ms': 5.0,
        },
    }])
    _gql_run, gql_obs = run_graphql_security(project, str(user.id), [{
        'ref': 'gql-own-rest-transition',
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': '/graphql',
        'session_ref': 'session-rest-a',
        'operation_type': 'query',
        'operation_name': 'Record',
        'field_path': 'record.id',
        'expected_allowed': True,
        'server_accepted': True,
        'response_status': 200,
        'errors_count': 0,
        'field_authorized': True,
        'mutation_authorized': True,
        'sensitive_fields_requested': [],
        'sensitive_fields_returned': [],
        'introspection_requested': False,
        'introspection_expected_allowed': False,
        'batch_size': 1,
        'max_batch_size': 10,
        'depth': 2,
        'max_depth': 8,
        'complexity': 3,
        'max_complexity': 100,
    }])
    run, observations = run_cross_protocol_security(project, str(user.id), [{
        'ref': 'https-to-graphql',
        'identity': _identity(),
        'resource': _resource(),
        'session_ref': 'session-rest-a',
        'from_protocol': 'https',
        'to_protocol': 'graphql',
        'operation': 'read',
        'expected_allowed': False,
        'observed_allowed': False,
        'identity_consistent': False,
        'tenant_consistent': False,
        'session_bound': False,
        'source_observation_id': str(http_obs[0].id),
        'target_observation_id': str(gql_obs[0].id),
    }])
    assert run.summary == {'total': 1, 'passed': 1, 'failed': 0}
    assert observations[0].passed is True
    assert observations[0].semantic['identity_consistent'] is True
    assert observations[0].semantic['tenant_consistent'] is True
    assert observations[0].semantic['session_bound'] is True

@pytest.mark.parametrize(
    'document',
    [
        'query Record { record(id: "a1") { ...Loop } } fragment Loop on Record { ...Loop }',
        'query Record { record(id: "a1") { ...Missing } }',
    ],
)
def test_graphql_metrics_fail_closed_on_unsafe_fragment_graphs(document: str):
    result = evaluate_graphql_case({
        'ref': 'graphql-fragment-invalid',
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': '/graphql',
        'session_ref': 'session-a',
        'operation_type': 'query',
        'operation_name': 'Record',
        'document': document,
        'field_path': 'record',
        'expected_allowed': False,
        'server_accepted': False,
        'response_status': 400,
        'errors_count': 1,
        'field_authorized': False,
        'mutation_authorized': True,
        'sensitive_fields_requested': [],
        'sensitive_fields_returned': [],
        'introspection_requested': False,
        'introspection_expected_allowed': False,
        'batch_size': 1,
        'max_batch_size': 10,
        'depth': 1,
        'max_depth': 8,
        'complexity': 1,
        'max_complexity': 100,
    })
    assert result['passed'] is False
    assert 'could not be parsed deterministically' in result['reason']

def test_graphql_schema_inventory_is_structural_bounded_and_value_free():
    inventory = graphql_schema_inventory(schema_sdl='''
        type Record { id: ID!, value: String!, related(limit: Int): Record }
        type Query { record(id: ID!): Record }
    ''')
    assert inventory['source'] == 'sdl'
    assert inventory['type_count'] >= 4
    assert inventory['field_count'] >= 4
    assert inventory['argument_count'] >= 2
    assert len(inventory['sha256']) == 64
    rendered = str(inventory)
    assert 'record' in rendered
    assert 'related' in rendered
    assert 'limit' in rendered
    assert 'alpha-secret' not in rendered

@pytest.mark.django_db
def test_cross_protocol_target_escalation_is_not_hidden_by_denied_source():
    user, project = _user_project('protocol-target-escalation')
    _gql_run, gql_obs = run_graphql_security(project, str(user.id), [{
        'ref': 'gql-source-denied',
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': '/graphql',
        'session_ref': 'session-a',
        'operation_type': 'query',
        'operation_name': 'Record',
        'field_path': 'record.id',
        'expected_allowed': False,
        'server_accepted': False,
        'response_status': 403,
        'errors_count': 1,
        'field_authorized': False,
        'mutation_authorized': True,
        'sensitive_fields_requested': [],
        'sensitive_fields_returned': [],
        'introspection_requested': False,
        'introspection_expected_allowed': False,
        'batch_size': 1,
        'max_batch_size': 10,
        'depth': 2,
        'max_depth': 8,
        'complexity': 3,
        'max_complexity': 100,
    }])
    assert gql_obs[0].passed is True

    _ws_run, ws_obs = run_websocket_security(project, str(user.id), [{
        'ref': 'ws-target-escalated',
        'identity': _identity(),
        'resource': _resource(),
        'channel': 'ws://fixture/ws/tenant-a/record-a',
        'session_ref': 'session-a',
        'origin': 'https://app.example',
        'allowed_origins': ['https://app.example'],
        'authentication_required': True,
        'authenticated': True,
        'session_state': 'active',
        'requested_action': 'subscribe',
        'expected_allowed': False,
        'server_accepted': True,
        'handshake_status': 101,
        'subscription_owner_ref': 'alice',
        'subscription_tenant_ref': 'tenant-a',
        'message_schema_valid': True,
        'message_authorized': True,
    }])
    assert ws_obs[0].passed is False

    _cross_run, cross_obs = run_cross_protocol_security(project, str(user.id), [{
        'ref': 'denied-source-to-escalated-target',
        'identity': _identity(),
        'resource': _resource(),
        'session_ref': 'session-a',
        'from_protocol': 'graphql',
        'to_protocol': 'websocket',
        'operation': 'subscribe',
        'expected_allowed': False,
        'observed_allowed': False,
        'identity_consistent': True,
        'tenant_consistent': True,
        'session_bound': True,
        'source_observation_id': str(gql_obs[0].id),
        'target_observation_id': str(ws_obs[0].id),
    }])
    assert cross_obs[0].passed is False
    assert cross_obs[0].semantic['source_validation_passed'] is True
    assert cross_obs[0].semantic['target_validation_passed'] is False
    assert cross_obs[0].observed_decision == 'allowed'
    assert 'target protocol observation failed' in cross_obs[0].reason

