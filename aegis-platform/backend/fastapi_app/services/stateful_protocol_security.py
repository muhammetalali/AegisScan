from __future__ import annotations

import json
from typing import Any, Callable

from django.db import transaction
from graphql import build_client_schema, build_schema, get_named_type, parse
from graphql.language.ast import FieldNode, FragmentSpreadNode, InlineFragmentNode

from enterprise.web_security_models import (
    WebSecurityObservation,
    WebSecurityValidationRun,
)
from fastapi_app.services.web_security_foundation import (
    CONTRACT_VERSION,
    canonical_digest,
    upsert_graph_snapshot,
)


def _identity(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get('identity')
    return value if isinstance(value, dict) else {}


def _resource(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get('resource')
    return value if isinstance(value, dict) else {}


def _decision(allowed: bool) -> str:
    return (
        WebSecurityObservation.Decision.ALLOWED
        if allowed
        else WebSecurityObservation.Decision.DENIED
    )


def evaluate_websocket_case(case: dict[str, Any]) -> dict[str, Any]:
    identity = _identity(case)
    resource = _resource(case)
    accepted = bool(case.get('server_accepted'))
    expected = bool(case.get('expected_allowed'))
    failures: list[str] = []

    origin = str(case.get('origin') or '')
    allowed_origins = {str(value) for value in (case.get('allowed_origins') or [])}
    if origin and allowed_origins and origin not in allowed_origins and accepted:
        failures.append('cross-origin WebSocket handshake was accepted')

    if bool(case.get('authentication_required', True)) and not bool(case.get('authenticated')) and accepted:
        failures.append('unauthenticated WebSocket session was accepted')

    session_state = str(case.get('session_state') or 'unknown')
    if session_state in {'expired', 'revoked'} and accepted:
        failures.append(f'{session_state} WebSocket session remained usable')

    identity_tenant = str(identity.get('tenant_ref') or '')
    subscription_tenant = str(case.get('subscription_tenant_ref') or resource.get('tenant_ref') or '')
    if identity_tenant and subscription_tenant and identity_tenant != subscription_tenant and accepted:
        failures.append('cross-tenant WebSocket subscription was accepted')

    owner = str(case.get('subscription_owner_ref') or resource.get('owner_ref') or '')
    identity_ref = str(identity.get('ref') or '')
    if owner and identity_ref and owner != identity_ref and not expected and accepted:
        failures.append('subscription ownership boundary was bypassed')

    if bool(case.get('reconnect')) and accepted and not bool(case.get('reconnect_reauthenticated')):
        failures.append('WebSocket reconnect succeeded without reauthentication')

    if accepted and not bool(case.get('message_schema_valid', True)):
        failures.append('schema-invalid WebSocket message was accepted')
    if accepted and not bool(case.get('message_authorized', True)):
        failures.append('message-level authorization was bypassed')

    if bool(case.get('binary')) and accepted and not bool(case.get('binary_allowed')):
        failures.append('unauthorized binary WebSocket frame was accepted')

    size = int(case.get('message_size_bytes') or 0)
    max_size = int(case.get('max_message_size_bytes') or 1_048_576)
    if size > max_size and accepted:
        failures.append('oversized WebSocket message was accepted')

    observed_messages = int(case.get('observed_messages') or 0)
    threshold = int(case.get('rate_limit_threshold') or 1000)
    if observed_messages > threshold and accepted and not bool(case.get('rate_limited')):
        failures.append('WebSocket rate threshold exceeded without enforcement')

    if accepted != expected:
        failures.append(
            'observed WebSocket authorization decision does not match expected policy'
        )

    semantic = {
        'protocol': 'websocket',
        'session_ref': str(case.get('session_ref') or ''),
        'origin': origin,
        'origin_allowed': not allowed_origins or origin in allowed_origins,
        'authenticated': bool(case.get('authenticated')),
        'session_state': session_state,
        'subscription_tenant_ref': subscription_tenant,
        'subscription_owner_ref': owner,
        'reconnect': bool(case.get('reconnect')),
        'reconnect_reauthenticated': bool(case.get('reconnect_reauthenticated')),
        'message_schema_valid': bool(case.get('message_schema_valid', True)),
        'message_authorized': bool(case.get('message_authorized', True)),
        'binary': bool(case.get('binary')),
        'message_size_bytes': size,
        'max_message_size_bytes': max_size,
        'observed_messages': observed_messages,
        'rate_limit_threshold': threshold,
        'rate_limited': bool(case.get('rate_limited')),
        'handshake_status': int(case.get('handshake_status') or 0),
        'close_code': case.get('close_code'),
        'failures': failures,
    }
    return {
        'passed': not failures,
        'expected_allowed': expected,
        'observed_decision': _decision(accepted),
        'semantic': semantic,
        'evidence_fingerprint': canonical_digest(semantic),
        'reason': '; '.join(failures) if failures else 'WebSocket invariants satisfied',
    }


def graphql_document_metrics(document: str) -> dict[str, Any]:
    parsed = parse(document)
    fragments = {
        definition.name.value: definition
        for definition in parsed.definitions
        if getattr(definition, 'name', None)
        and definition.__class__.__name__ == 'FragmentDefinitionNode'
    }
    fields: set[str] = set()

    def walk(selection_set, depth: int, seen: set[str]) -> tuple[int, int]:
        if selection_set is None:
            return depth, 0
        max_depth = depth
        complexity = 0
        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                name = selection.name.value
                fields.add(name)
                complexity += 1
                child_depth, child_complexity = walk(
                    selection.selection_set,
                    depth + 1,
                    seen,
                )
                max_depth = max(max_depth, child_depth)
                complexity += child_complexity
            elif isinstance(selection, InlineFragmentNode):
                child_depth, child_complexity = walk(
                    selection.selection_set,
                    depth,
                    seen,
                )
                max_depth = max(max_depth, child_depth)
                complexity += child_complexity
            elif isinstance(selection, FragmentSpreadNode):
                name = selection.name.value
                if name in seen:
                    raise ValueError('cyclic GraphQL fragment graph')
                if name not in fragments:
                    raise ValueError('unknown GraphQL fragment reference')
                child_depth, child_complexity = walk(
                    fragments[name].selection_set,
                    depth,
                    seen | {name},
                )
                max_depth = max(max_depth, child_depth)
                complexity += child_complexity
        return max_depth, complexity

    operations: list[dict[str, str]] = []
    depth = 0
    complexity = 0
    for definition in parsed.definitions:
        if definition.__class__.__name__ != 'OperationDefinitionNode':
            continue
        current_depth, current_complexity = walk(
            definition.selection_set,
            1,
            set(),
        )
        depth = max(depth, current_depth)
        complexity += current_complexity
        operation_value = getattr(definition.operation, 'value', str(definition.operation))
        operations.append({
            'type': str(operation_value),
            'name': definition.name.value if definition.name else 'anonymous',
        })

    return {
        'depth': depth,
        'complexity': complexity,
        'fields': sorted(fields),
        'introspection_requested': '__schema' in fields or '__type' in fields,
        'operations': operations,
    }



_MAX_SCHEMA_BYTES = 1_048_576
_MAX_SCHEMA_TYPES = 512
_MAX_SCHEMA_FIELDS = 4_000
_MAX_SCHEMA_ARGUMENTS = 4_000


def graphql_schema_inventory(
    *,
    schema_sdl: str = '',
    schema_introspection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = ''
    if schema_sdl:
        encoded = schema_sdl.encode('utf-8')
        if len(encoded) > _MAX_SCHEMA_BYTES:
            raise ValueError('GraphQL SDL exceeds bounded schema analysis size')
        schema = build_schema(schema_sdl)
        source = 'sdl'
    elif schema_introspection:
        rendered = json.dumps(
            schema_introspection,
            ensure_ascii=False,
            sort_keys=True,
            separators=(',', ':'),
        ).encode('utf-8')
        if len(rendered) > _MAX_SCHEMA_BYTES:
            raise ValueError('GraphQL introspection exceeds bounded schema analysis size')
        payload: Any = schema_introspection
        if isinstance(payload, dict) and isinstance(payload.get('data'), dict):
            payload = payload['data']
        if not isinstance(payload, dict) or not isinstance(payload.get('__schema'), dict):
            raise ValueError('GraphQL introspection payload does not contain __schema')
        schema = build_client_schema(payload)
        source = 'introspection'
    else:
        return {}

    types: list[dict[str, Any]] = []
    field_count = 0
    argument_count = 0
    for type_name, type_obj in sorted(schema.type_map.items()):
        if type_name.startswith('__'):
            continue
        if len(types) >= _MAX_SCHEMA_TYPES:
            raise ValueError('GraphQL schema type count exceeds bounded analysis limit')
        fields_out: list[dict[str, Any]] = []
        fields = getattr(type_obj, 'fields', None)
        if isinstance(fields, dict):
            for field_name, field_obj in sorted(fields.items()):
                field_count += 1
                if field_count > _MAX_SCHEMA_FIELDS:
                    raise ValueError('GraphQL schema field count exceeds bounded analysis limit')
                args_out: list[dict[str, str]] = []
                args = getattr(field_obj, 'args', None)
                if isinstance(args, dict):
                    for arg_name, arg_obj in sorted(args.items()):
                        argument_count += 1
                        if argument_count > _MAX_SCHEMA_ARGUMENTS:
                            raise ValueError('GraphQL schema argument count exceeds bounded analysis limit')
                        arg_type = getattr(arg_obj, 'type', None)
                        args_out.append({
                            'name': str(arg_name),
                            'type': str(arg_type),
                            'named_type': str(getattr(get_named_type(arg_type), 'name', '')),
                        })
                field_type = getattr(field_obj, 'type', None)
                fields_out.append({
                    'name': str(field_name),
                    'type': str(field_type),
                    'named_type': str(getattr(get_named_type(field_type), 'name', '')),
                    'arguments': args_out,
                })
        types.append({
            'name': str(type_name),
            'kind': type_obj.__class__.__name__,
            'fields': fields_out,
        })

    canonical = {
        'source': source,
        'types': types,
    }
    return {
        'source': source,
        'sha256': canonical_digest(canonical),
        'type_count': len(types),
        'field_count': field_count,
        'argument_count': argument_count,
        'types': types,
    }


def evaluate_graphql_case(case: dict[str, Any]) -> dict[str, Any]:
    identity = _identity(case)
    resource = _resource(case)
    expected = bool(case.get('expected_allowed'))
    accepted = bool(case.get('server_accepted'))
    failures: list[str] = []

    schema_inventory: dict[str, Any] = {}
    if case.get('schema_sdl') or case.get('schema_introspection'):
        try:
            schema_inventory = graphql_schema_inventory(
                schema_sdl=str(case.get('schema_sdl') or ''),
                schema_introspection=(
                    case.get('schema_introspection')
                    if isinstance(case.get('schema_introspection'), dict)
                    else None
                ),
            )
        except Exception:
            failures.append('GraphQL schema could not be analyzed deterministically')

    document_metrics: dict[str, Any] | None = None
    document = str(case.get('document') or '')
    if document:
        try:
            document_metrics = graphql_document_metrics(document)
        except Exception:
            failures.append('GraphQL document could not be parsed deterministically')
        else:
            operations = document_metrics['operations']
            declared = {
                'type': str(case.get('operation_type') or ''),
                'name': str(case.get('operation_name') or ''),
            }
            if declared not in operations:
                failures.append('declared GraphQL operation metadata does not match document')

    if accepted != expected:
        failures.append('observed GraphQL authorization decision does not match expected policy')

    identity_tenant = str(identity.get('tenant_ref') or '')
    resource_tenant = str(resource.get('tenant_ref') or '')
    if identity_tenant and resource_tenant and identity_tenant != resource_tenant and accepted:
        failures.append('cross-tenant GraphQL resource access was accepted')

    if accepted and not bool(case.get('field_authorized', True)):
        failures.append('GraphQL field-level authorization was bypassed')

    operation_type = str(case.get('operation_type') or 'query')
    if (
        operation_type == 'mutation'
        and accepted
        and not bool(case.get('mutation_authorized', True))
    ):
        failures.append('unauthorized GraphQL mutation was accepted')

    subscription_tenant = str(case.get('subscription_tenant_ref') or '')
    if (
        operation_type == 'subscription'
        and accepted
        and identity_tenant
        and subscription_tenant
        and identity_tenant != subscription_tenant
    ):
        failures.append('cross-tenant GraphQL subscription was accepted')

    owner = str(case.get('subscription_owner_ref') or '')
    identity_ref = str(identity.get('ref') or '')
    if (
        operation_type == 'subscription'
        and accepted
        and owner
        and identity_ref
        and owner != identity_ref
        and not expected
    ):
        failures.append('GraphQL subscription ownership boundary was bypassed')

    sensitive_requested = {
        str(value) for value in (case.get('sensitive_fields_requested') or [])
    }
    sensitive_returned = {
        str(value) for value in (case.get('sensitive_fields_returned') or [])
    }
    if sensitive_returned and (
        not expected or not bool(case.get('field_authorized', True))
    ):
        failures.append(
            'sensitive GraphQL fields were returned without field authorization: '
            + ', '.join(sorted(sensitive_returned))
        )

    introspection_requested = (
        bool(document_metrics.get('introspection_requested'))
        if document_metrics is not None
        else bool(case.get('introspection_requested'))
    )
    if (
        introspection_requested
        and accepted
        and not bool(case.get('introspection_expected_allowed'))
    ):
        failures.append('GraphQL introspection was exposed contrary to policy')

    batch_size = int(case.get('batch_size') or 1)
    max_batch_size = int(case.get('max_batch_size') or 10)
    if accepted and batch_size > max_batch_size:
        failures.append('GraphQL batch size limit was bypassed')

    depth = (
        int(document_metrics['depth'])
        if document_metrics is not None
        else int(case.get('depth') or 1)
    )
    max_depth = int(case.get('max_depth') or 12)
    if accepted and depth > max_depth:
        failures.append('GraphQL depth limit was bypassed')

    complexity = (
        int(document_metrics['complexity'])
        if document_metrics is not None
        else int(case.get('complexity') or 1)
    )
    max_complexity = int(case.get('max_complexity') or 1000)
    if accepted and complexity > max_complexity:
        failures.append('GraphQL complexity limit was bypassed')

    semantic = {
        'protocol': 'graphql',
        'session_ref': str(case.get('session_ref') or ''),
        'operation_type': operation_type,
        'operation_name': str(case.get('operation_name') or ''),
        'field_path': str(case.get('field_path') or ''),
        'response_status': int(case.get('response_status') or 0),
        'errors_count': int(case.get('errors_count') or 0),
        'field_authorized': bool(case.get('field_authorized', True)),
        'mutation_authorized': bool(case.get('mutation_authorized', True)),
        'identity_tenant_ref': identity_tenant,
        'resource_tenant_ref': resource_tenant,
        'subscription_tenant_ref': subscription_tenant,
        'subscription_owner_ref': owner,
        'sensitive_fields_requested': sorted(sensitive_requested),
        'sensitive_fields_returned': sorted(sensitive_returned),
        'introspection_requested': introspection_requested,
        'document_fields': (
            document_metrics['fields'] if document_metrics is not None else []
        ),
        'schema_source': str(schema_inventory.get('source') or ''),
        'schema_sha256': str(schema_inventory.get('sha256') or ''),
        'schema_type_count': int(schema_inventory.get('type_count') or 0),
        'schema_field_count': int(schema_inventory.get('field_count') or 0),
        'schema_argument_count': int(schema_inventory.get('argument_count') or 0),
        'introspection_expected_allowed': bool(
            case.get('introspection_expected_allowed')
        ),
        'batch_size': batch_size,
        'max_batch_size': max_batch_size,
        'depth': depth,
        'max_depth': max_depth,
        'complexity': complexity,
        'max_complexity': max_complexity,
        'failures': failures,
    }
    return {
        'passed': not failures,
        'expected_allowed': expected,
        'observed_decision': _decision(accepted),
        'semantic': semantic,
        'evidence_fingerprint': canonical_digest(semantic),
        'reason': '; '.join(failures) if failures else 'GraphQL invariants satisfied',
        'schema_inventory': schema_inventory,
    }


def evaluate_cross_protocol_case(case: dict[str, Any]) -> dict[str, Any]:
    expected = bool(case.get('expected_allowed'))
    observed = bool(case.get('observed_allowed'))
    failures: list[str] = []
    if expected != observed:
        failures.append('cross-protocol authorization decision changed unexpectedly')
    if not bool(case.get('identity_consistent', True)):
        failures.append('identity changed across protocol transition')
    if not bool(case.get('tenant_consistent', True)):
        failures.append('tenant context changed across protocol transition')
    if not bool(case.get('session_bound', True)):
        failures.append('target protocol session is not bound to source session')
    if not bool(case.get('source_validation_passed', True)):
        failures.append('source protocol observation failed its own validation')
    if not bool(case.get('target_validation_passed', True)):
        failures.append('target protocol observation failed its own validation')

    semantic = {
        'from_protocol': str(case.get('from_protocol') or ''),
        'to_protocol': str(case.get('to_protocol') or ''),
        'session_ref': str(case.get('session_ref') or ''),
        'identity_consistent': bool(case.get('identity_consistent', True)),
        'tenant_consistent': bool(case.get('tenant_consistent', True)),
        'session_bound': bool(case.get('session_bound', True)),
        'source_validation_passed': bool(case.get('source_validation_passed', True)),
        'target_validation_passed': bool(case.get('target_validation_passed', True)),
        'source_observation_id': str(case.get('source_observation_id') or ''),
        'target_observation_id': str(case.get('target_observation_id') or ''),
        'source_evidence_ref': str(case.get('source_evidence_ref') or ''),
        'target_evidence_ref': str(case.get('target_evidence_ref') or ''),
        'failures': failures,
    }
    return {
        'passed': not failures,
        'expected_allowed': expected,
        'observed_decision': _decision(observed),
        'semantic': semantic,
        'evidence_fingerprint': canonical_digest(semantic),
        'reason': '; '.join(failures) if failures else 'cross-protocol invariants satisfied',
    }



def _protocol_for_observation(observation: WebSecurityObservation) -> str:
    kind = observation.run.kind
    if kind == WebSecurityValidationRun.Kind.WEBSOCKET_SECURITY:
        return 'websocket'
    if kind == WebSecurityValidationRun.Kind.GRAPHQL_SECURITY:
        return 'graphql'
    if kind == WebSecurityValidationRun.Kind.AUTHORIZATION_MATRIX:
        protocol = str((observation.semantic or {}).get('protocol') or '').strip().lower()
        return protocol if protocol in {'browser', 'http', 'https', 'graphql', 'websocket'} else ''
    return ''


def _hydrate_cross_protocol_case(project, case: dict[str, Any]) -> dict[str, Any]:
    source_id = str(case.get('source_observation_id') or '').strip()
    target_id = str(case.get('target_observation_id') or '').strip()
    if not source_id or not target_id:
        raise ValueError('cross-protocol validation requires source and target observation IDs')

    observations = {
        str(row.id): row
        for row in WebSecurityObservation.objects.select_related('run').filter(
            id__in=[source_id, target_id],
            run__project=project,
        )
    }
    source = observations.get(source_id)
    target = observations.get(target_id)
    if source is None or target is None:
        raise ValueError('cross-protocol observations must exist in the same project')

    from_protocol = str(case.get('from_protocol') or '').strip().lower()
    to_protocol = str(case.get('to_protocol') or '').strip().lower()
    if _protocol_for_observation(source) != from_protocol:
        raise ValueError('source observation protocol does not match transition source')
    if _protocol_for_observation(target) != to_protocol:
        raise ValueError('target observation protocol does not match transition target')

    identity = _identity(case)
    resource = _resource(case)
    identity_ref = str(identity.get('ref') or '')
    identity_tenant = str(identity.get('tenant_ref') or '')
    resource_ref = str(resource.get('ref') or '')
    resource_tenant = str(resource.get('tenant_ref') or '')

    identity_consistent = bool(
        identity_ref
        and source.identity_ref == identity_ref
        and target.identity_ref == identity_ref
        and source.identity_type == target.identity_type == str(identity.get('type') or '')
        and source.role == target.role == str(identity.get('role') or '')
    )
    tenant_consistent = bool(
        identity_tenant
        and resource_tenant
        and source.tenant_ref == target.tenant_ref == identity_tenant
        and source.resource_tenant_ref == target.resource_tenant_ref == resource_tenant
    )
    resource_consistent = bool(
        resource_ref
        and source.resource_ref == target.resource_ref == resource_ref
    )

    session_ref = str(case.get('session_ref') or '')
    source_session = str((source.semantic or {}).get('session_ref') or '')
    target_session = str((target.semantic or {}).get('session_ref') or '')
    session_bound = bool(
        session_ref
        and source_session == session_ref
        and target_session == session_ref
    )

    observed_allowed = target.observed_decision == WebSecurityObservation.Decision.ALLOWED
    expected_allowed = bool(target.expected_allowed)

    hydrated = dict(case)
    hydrated.update({
        'expected_allowed': expected_allowed,
        'observed_allowed': observed_allowed,
        'source_validation_passed': bool(source.passed),
        'target_validation_passed': bool(target.passed),
        'identity_consistent': identity_consistent,
        'tenant_consistent': tenant_consistent and resource_consistent,
        'session_bound': session_bound,
        'source_evidence_ref': source.evidence_fingerprint,
        'target_evidence_ref': target.evidence_fingerprint,
    })
    return hydrated


def _common_nodes(case: dict[str, Any], source: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    identity = _identity(case)
    resource = _resource(case)
    identity_ref = str(identity.get('ref') or '')
    resource_ref = str(resource.get('ref') or '')
    identity_tenant = str(identity.get('tenant_ref') or '')
    resource_tenant = str(resource.get('tenant_ref') or '')
    nodes = [
        {
            'plane': 'identity',
            'kind': 'identity',
            'external_ref': f'identity:{identity_ref}',
            'label': identity_ref,
            'tenant_ref': identity_tenant,
            'properties': {
                'identity_type': identity.get('type'),
                'role': identity.get('role'),
            },
            'provenance': {'source': source},
        },
        {
            'plane': 'application',
            'kind': 'resource',
            'external_ref': f'resource:{resource_ref}',
            'label': resource_ref,
            'tenant_ref': resource_tenant,
            'properties': {'resource_type': resource.get('type')},
            'provenance': {'source': source},
        },
    ]
    edges: list[dict[str, Any]] = []
    return nodes, edges


def _project_websocket_graph(project, case: dict[str, Any], result: dict[str, Any]) -> None:
    identity = _identity(case)
    resource = _resource(case)
    nodes, edges = _common_nodes(case, 'websocket_security')
    channel = str(case.get('channel') or '')
    channel_ref = f'websocket:{canonical_digest(channel)[:32]}'
    nodes.append({
        'plane': 'application',
        'kind': 'websocket_channel',
        'external_ref': channel_ref,
        'label': channel,
        'protocol': 'websocket',
        'tenant_ref': str(case.get('subscription_tenant_ref') or ''),
        'properties': {
            'requested_action': case.get('requested_action'),
            'last_validation_passed': result['passed'],
        },
        'provenance': {'source': 'websocket_security'},
    })
    edges.extend([
        {
            'source_ref': f'identity:{identity.get("ref")}',
            'target_ref': channel_ref,
            'relation': 'subscribes_to',
            'properties': {'case_ref': case.get('ref')},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'websocket_security'},
        },
        {
            'source_ref': channel_ref,
            'target_ref': f'resource:{resource.get("ref")}',
            'relation': 'streams_resource',
            'properties': {},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'websocket_security'},
        },
    ])
    upsert_graph_snapshot(project, nodes, edges)


def _project_graphql_graph(project, case: dict[str, Any], result: dict[str, Any]) -> None:
    identity = _identity(case)
    resource = _resource(case)
    nodes, edges = _common_nodes(case, 'graphql_security')
    operation_key = {
        'endpoint': case.get('endpoint'),
        'operation_type': case.get('operation_type'),
        'operation_name': case.get('operation_name'),
        'field_path': case.get('field_path'),
    }
    operation_ref = f'graphql:{canonical_digest(operation_key)[:32]}'
    nodes.append({
        'plane': 'application',
        'kind': 'graphql_operation',
        'external_ref': operation_ref,
        'label': str(case.get('operation_name') or ''),
        'protocol': 'graphql',
        'tenant_ref': str(resource.get('tenant_ref') or ''),
        'properties': {
            **operation_key,
            'last_validation_passed': result['passed'],
        },
        'provenance': {'source': 'graphql_security'},
    })
    edges.extend([
        {
            'source_ref': f'identity:{identity.get("ref")}',
            'target_ref': operation_ref,
            'relation': 'invokes',
            'properties': {'case_ref': case.get('ref')},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'graphql_security'},
        },
        {
            'source_ref': operation_ref,
            'target_ref': f'resource:{resource.get("ref")}',
            'relation': 'operates_on',
            'properties': {},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'graphql_security'},
        },
    ])

    inventory = result.get('schema_inventory') if isinstance(result.get('schema_inventory'), dict) else {}
    schema_types = inventory.get('types') if isinstance(inventory.get('types'), list) else []
    schema_source = str(inventory.get('source') or '')
    schema_sha256 = str(inventory.get('sha256') or '')
    endpoint = str(case.get('endpoint') or '')
    type_refs: dict[str, str] = {}

    for type_item in schema_types:
        if not isinstance(type_item, dict):
            continue
        type_name = str(type_item.get('name') or '')
        if not type_name:
            continue
        type_ref = f'graphql-type:{canonical_digest([endpoint, type_name])[:32]}'
        type_refs[type_name] = type_ref
        nodes.append({
            'plane': 'application',
            'kind': 'graphql_type',
            'external_ref': type_ref,
            'label': type_name,
            'protocol': 'graphql',
            'tenant_ref': '',
            'properties': {
                'schema_kind': str(type_item.get('kind') or ''),
                'schema_sha256': schema_sha256,
            },
            'provenance': {
                'source': 'graphql_schema',
                'schema_source': schema_source,
            },
        })

    root_type = {
        'query': 'Query',
        'mutation': 'Mutation',
        'subscription': 'Subscription',
    }.get(str(case.get('operation_type') or '').lower(), '')
    if root_type and root_type in type_refs:
        edges.append({
            'source_ref': operation_ref,
            'target_ref': type_refs[root_type],
            'relation': 'defined_on',
            'properties': {},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'graphql_schema'},
        })

    for type_item in schema_types:
        if not isinstance(type_item, dict):
            continue
        type_name = str(type_item.get('name') or '')
        type_ref = type_refs.get(type_name)
        if not type_ref:
            continue
        fields = type_item.get('fields') if isinstance(type_item.get('fields'), list) else []
        for field_item in fields:
            if not isinstance(field_item, dict):
                continue
            field_name = str(field_item.get('name') or '')
            if not field_name:
                continue
            field_ref = f'graphql-field:{canonical_digest([endpoint, type_name, field_name])[:32]}'
            nodes.append({
                'plane': 'application',
                'kind': 'graphql_field',
                'external_ref': field_ref,
                'label': f'{type_name}.{field_name}',
                'protocol': 'graphql',
                'tenant_ref': '',
                'properties': {
                    'return_type': str(field_item.get('type') or ''),
                    'schema_sha256': schema_sha256,
                },
                'provenance': {'source': 'graphql_schema'},
            })
            edges.append({
                'source_ref': type_ref,
                'target_ref': field_ref,
                'relation': 'has_field',
                'properties': {},
                'evidence_refs': [result['evidence_fingerprint']],
                'provenance': {'source': 'graphql_schema'},
            })
            return_type_ref = type_refs.get(str(field_item.get('named_type') or ''))
            if return_type_ref:
                edges.append({
                    'source_ref': field_ref,
                    'target_ref': return_type_ref,
                    'relation': 'returns_type',
                    'properties': {},
                    'evidence_refs': [result['evidence_fingerprint']],
                    'provenance': {'source': 'graphql_schema'},
                })

            arguments = (
                field_item.get('arguments')
                if isinstance(field_item.get('arguments'), list)
                else []
            )
            for arg_item in arguments:
                if not isinstance(arg_item, dict):
                    continue
                arg_name = str(arg_item.get('name') or '')
                if not arg_name:
                    continue
                arg_ref = f'graphql-argument:{canonical_digest([endpoint, type_name, field_name, arg_name])[:32]}'
                nodes.append({
                    'plane': 'application',
                    'kind': 'graphql_argument',
                    'external_ref': arg_ref,
                    'label': f'{type_name}.{field_name}({arg_name})',
                    'protocol': 'graphql',
                    'tenant_ref': '',
                    'properties': {
                        'argument_type': str(arg_item.get('type') or ''),
                        'schema_sha256': schema_sha256,
                    },
                    'provenance': {'source': 'graphql_schema'},
                })
                edges.append({
                    'source_ref': field_ref,
                    'target_ref': arg_ref,
                    'relation': 'accepts_argument',
                    'properties': {},
                    'evidence_refs': [result['evidence_fingerprint']],
                    'provenance': {'source': 'graphql_schema'},
                })
                argument_type_ref = type_refs.get(str(arg_item.get('named_type') or ''))
                if argument_type_ref:
                    edges.append({
                        'source_ref': arg_ref,
                        'target_ref': argument_type_ref,
                        'relation': 'argument_type',
                        'properties': {},
                        'evidence_refs': [result['evidence_fingerprint']],
                        'provenance': {'source': 'graphql_schema'},
                    })

    upsert_graph_snapshot(project, nodes, edges)


def _project_cross_protocol_graph(project, case: dict[str, Any], result: dict[str, Any]) -> None:
    identity = _identity(case)
    lineage_refs = [
        ref
        for ref in (
            str(case.get('source_evidence_ref') or ''),
            str(case.get('target_evidence_ref') or ''),
            str(result.get('evidence_fingerprint') or ''),
        )
        if ref
    ]
    resource = _resource(case)
    nodes, edges = _common_nodes(case, 'cross_protocol')
    session_ref = str(case.get('session_ref') or '')
    session_node = f'session:{session_ref}'
    from_state = f'protocol-state:{canonical_digest([session_ref, case.get("from_protocol")])[:32]}'
    to_state = f'protocol-state:{canonical_digest([session_ref, case.get("to_protocol")])[:32]}'
    nodes.extend([
        {
            'plane': 'identity',
            'kind': 'session',
            'external_ref': session_node,
            'label': session_ref,
            'tenant_ref': str(identity.get('tenant_ref') or ''),
            'properties': {},
            'provenance': {'source': 'cross_protocol'},
        },
        {
            'plane': 'application',
            'kind': 'channel',
            'external_ref': from_state,
            'label': str(case.get('from_protocol') or ''),
            'protocol': str(case.get('from_protocol') or ''),
            'properties': {'session_ref': session_ref},
            'provenance': {'source': 'cross_protocol'},
        },
        {
            'plane': 'application',
            'kind': 'channel',
            'external_ref': to_state,
            'label': str(case.get('to_protocol') or ''),
            'protocol': str(case.get('to_protocol') or ''),
            'properties': {
                'session_ref': session_ref,
                'last_validation_passed': result['passed'],
            },
            'provenance': {'source': 'cross_protocol'},
        },
    ])
    edges.extend([
        {
            'source_ref': f'identity:{identity.get("ref")}',
            'target_ref': session_node,
            'relation': 'owns_session',
            'properties': {},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'cross_protocol'},
        },
        {
            'source_ref': session_node,
            'target_ref': from_state,
            'relation': 'active_on',
            'properties': {},
            'evidence_refs': [],
            'provenance': {'source': 'cross_protocol'},
        },
        {
            'source_ref': from_state,
            'target_ref': to_state,
            'relation': 'transitions_to',
            'properties': {'operation': case.get('operation')},
            'evidence_refs': lineage_refs,
            'provenance': {'source': 'cross_protocol'},
        },
        {
            'source_ref': to_state,
            'target_ref': f'resource:{resource.get("ref")}',
            'relation': 'targets',
            'properties': {},
            'evidence_refs': lineage_refs,
            'provenance': {'source': 'cross_protocol'},
        },
    ])
    upsert_graph_snapshot(project, nodes, edges)


def _observation_for(
    run: WebSecurityValidationRun,
    case: dict[str, Any],
    result: dict[str, Any],
    *,
    endpoint: str,
    method: str,
    operation: str,
) -> WebSecurityObservation:
    identity = _identity(case)
    resource = _resource(case)
    return WebSecurityObservation(
        run=run,
        case_ref=str(case.get('ref') or ''),
        identity_ref=str(identity.get('ref') or ''),
        identity_type=str(identity.get('type') or ''),
        role=str(identity.get('role') or ''),
        tenant_ref=str(identity.get('tenant_ref') or ''),
        resource_ref=str(resource.get('ref') or ''),
        resource_tenant_ref=str(resource.get('tenant_ref') or ''),
        endpoint=endpoint,
        method=method,
        operation=operation,
        expected_allowed=result['expected_allowed'],
        observed_decision=result['observed_decision'],
        passed=result['passed'],
        semantic=result['semantic'],
        evidence_fingerprint=result['evidence_fingerprint'],
        reason=result['reason'],
    )


@transaction.atomic
def _run_cases(
    project,
    actor_id: str,
    cases: list[dict[str, Any]],
    *,
    kind: str,
    evaluator: Callable[[dict[str, Any]], dict[str, Any]],
    projector: Callable[[Any, dict[str, Any], dict[str, Any]], None],
    endpoint_for: Callable[[dict[str, Any]], str],
    method_for: Callable[[dict[str, Any]], str],
    operation_for: Callable[[dict[str, Any]], str],
    governance: dict[str, Any] | None = None,
) -> tuple[WebSecurityValidationRun, list[WebSecurityObservation]]:
    evaluated: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for case in cases:
        result = evaluator(case)
        evaluated.append((case, result))
        projector(project, case, result)

    summary = {
        'total': len(evaluated),
        'passed': sum(1 for _case, result in evaluated if result['passed']),
        'failed': sum(1 for _case, result in evaluated if not result['passed']),
    }
    if governance is not None:
        summary['execution_budget'] = {
            'profile_id': str(governance.get('profile_id') or ''),
            'profile_sha256': str(governance.get('profile_sha256') or ''),
            'environment': str(governance.get('environment') or ''),
            'allowed': bool(governance.get('allowed')),
        }
    run = WebSecurityValidationRun.objects.create(
        project=project,
        kind=kind,
        status=WebSecurityValidationRun.Status.COMPLETED,
        contract_version=CONTRACT_VERSION,
        input_sha256=canonical_digest(cases),
        summary=summary,
        created_by_id=actor_id,
    )
    observations = [
        _observation_for(
            run,
            case,
            result,
            endpoint=endpoint_for(case),
            method=method_for(case),
            operation=operation_for(case),
        )
        for case, result in evaluated
    ]
    WebSecurityObservation.objects.bulk_create(observations)
    return run, observations


def run_websocket_security(project, actor_id: str, cases: list[dict[str, Any]], governance: dict[str, Any] | None = None):
    return _run_cases(
        project,
        actor_id,
        cases,
        kind=WebSecurityValidationRun.Kind.WEBSOCKET_SECURITY,
        evaluator=evaluate_websocket_case,
        projector=_project_websocket_graph,
        endpoint_for=lambda case: str(case.get('channel') or ''),
        method_for=lambda _case: 'WEBSOCKET',
        operation_for=lambda case: str(case.get('requested_action') or ''),
        governance=governance,
    )


def run_graphql_security(project, actor_id: str, cases: list[dict[str, Any]], governance: dict[str, Any] | None = None):
    return _run_cases(
        project,
        actor_id,
        cases,
        kind=WebSecurityValidationRun.Kind.GRAPHQL_SECURITY,
        evaluator=evaluate_graphql_case,
        projector=_project_graphql_graph,
        endpoint_for=lambda case: str(case.get('endpoint') or ''),
        method_for=lambda _case: 'POST',
        operation_for=lambda case: str(case.get('operation_name') or ''),
        governance=governance,
    )


def run_cross_protocol_security(project, actor_id: str, cases: list[dict[str, Any]], governance: dict[str, Any] | None = None):
    hydrated_cases = [_hydrate_cross_protocol_case(project, case) for case in cases]
    return _run_cases(
        project,
        actor_id,
        hydrated_cases,
        kind=WebSecurityValidationRun.Kind.CROSS_PROTOCOL,
        evaluator=evaluate_cross_protocol_case,
        projector=_project_cross_protocol_graph,
        endpoint_for=lambda case: (
            f'{case.get("from_protocol")}->{case.get("to_protocol")}'
        ),
        method_for=lambda _case: 'STATE',
        operation_for=lambda case: str(case.get('operation') or ''),
        governance=governance,
    )
