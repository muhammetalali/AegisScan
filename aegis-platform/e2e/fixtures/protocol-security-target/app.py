from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from graphql import GraphQLError, build_schema, graphql_sync, parse
from graphql.language.ast import FieldNode, FragmentSpreadNode, InlineFragmentNode

app = FastAPI(title='Aegis Protocol Security Fixture')

ALLOWED_ORIGIN = 'http://127.0.0.1:18085'
TOKENS = {
    'alice-token': {'ref': 'alice', 'tenant': 'tenant-a', 'role': 'viewer', 'state': 'active'},
    'bob-token': {'ref': 'bob', 'tenant': 'tenant-b', 'role': 'viewer', 'state': 'active'},
    'admin-token': {'ref': 'admin', 'tenant': 'tenant-a', 'role': 'admin', 'state': 'active'},
    'expired-token': {'ref': 'alice', 'tenant': 'tenant-a', 'role': 'viewer', 'state': 'expired'},
}
RECORDS = {
    'a1': {'id': 'a1', 'tenant': 'tenant-a', 'owner': 'alice', 'value': 'alpha', 'secret': 'alpha-secret'},
    'b1': {'id': 'b1', 'tenant': 'tenant-b', 'owner': 'bob', 'value': 'bravo', 'secret': 'bravo-secret'},
}

SCHEMA = build_schema(
    '''
    type Record {
      id: ID!
      tenant: String!
      owner: String!
      value: String!
      secret: String!
      related: Record
    }

    type Query {
      record(id: ID!): Record
      records: [Record!]!
    }

    type Mutation {
      updateRecord(id: ID!, value: String!): Record
    }

    type Subscription {
      recordChanged(id: ID!): Record
    }
    '''
)


def _identity_from_header(value: str | None) -> dict[str, str] | None:
    raw = str(value or '')
    if not raw.lower().startswith('bearer '):
        return None
    return TOKENS.get(raw.split(None, 1)[1].strip())


def _context(request: Request, vulnerable: bool) -> dict[str, Any]:
    return {
        'identity': _identity_from_header(request.headers.get('authorization')),
        'vulnerable': vulnerable,
    }


def _record_for(context: dict[str, Any], record_id: str) -> dict[str, Any] | None:
    record = RECORDS.get(record_id)
    if record is None:
        return None
    if context['vulnerable']:
        return dict(record)
    identity = context.get('identity')
    if not identity or identity.get('state') != 'active':
        raise GraphQLError('Unauthorized')
    if identity.get('tenant') != record['tenant']:
        raise GraphQLError('Forbidden tenant')
    if identity.get('role') != 'admin' and identity.get('ref') != record['owner']:
        raise GraphQLError('Forbidden owner')
    return dict(record)


def _query_record(info, id: str):
    return _record_for(info.context, id)


def _query_records(info):
    if info.context['vulnerable']:
        return [dict(value) for value in RECORDS.values()]
    identity = info.context.get('identity')
    if not identity or identity.get('state') != 'active':
        raise GraphQLError('Unauthorized')
    return [
        dict(value)
        for value in RECORDS.values()
        if value['tenant'] == identity['tenant']
        and (identity['role'] == 'admin' or value['owner'] == identity['ref'])
    ]


def _mutate_record(info, id: str, value: str):
    record = RECORDS.get(id)
    if record is None:
        return None
    identity = info.context.get('identity')
    if not info.context['vulnerable']:
        if not identity or identity.get('state') != 'active':
            raise GraphQLError('Unauthorized')
        if identity.get('role') != 'admin' or identity.get('tenant') != record['tenant']:
            raise GraphQLError('Mutation forbidden')
    result = dict(record)
    result['value'] = value
    return result


def _resolve_secret(record, info):
    if info.context['vulnerable']:
        return record['secret']
    identity = info.context.get('identity')
    if not identity or identity.get('role') != 'admin':
        raise GraphQLError('Sensitive field forbidden')
    return record['secret']


SCHEMA.get_type('Query').fields['record'].resolve = _query_record
SCHEMA.get_type('Query').fields['records'].resolve = _query_records
SCHEMA.get_type('Mutation').fields['updateRecord'].resolve = _mutate_record
SCHEMA.get_type('Record').fields['secret'].resolve = _resolve_secret
SCHEMA.get_type('Record').fields['related'].resolve = lambda record, info: record


def _metrics(query: str) -> tuple[int, int]:
    document = parse(query)
    fragments = {
        definition.name.value: definition
        for definition in document.definitions
        if getattr(definition, 'name', None)
        and definition.__class__.__name__ == 'FragmentDefinitionNode'
    }

    def walk(selection_set, depth: int, seen: set[str]) -> tuple[int, int]:
        if selection_set is None:
            return depth, 0
        max_depth = depth
        complexity = 0
        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                complexity += 1
                child_depth, child_complexity = walk(selection.selection_set, depth + 1, seen)
                max_depth = max(max_depth, child_depth)
                complexity += child_complexity
            elif isinstance(selection, InlineFragmentNode):
                child_depth, child_complexity = walk(selection.selection_set, depth, seen)
                max_depth = max(max_depth, child_depth)
                complexity += child_complexity
            elif isinstance(selection, FragmentSpreadNode):
                name = selection.name.value
                if name in seen or name not in fragments:
                    continue
                child_depth, child_complexity = walk(
                    fragments[name].selection_set,
                    depth,
                    seen | {name},
                )
                max_depth = max(max_depth, child_depth)
                complexity += child_complexity
        return max_depth, complexity

    depth = 0
    complexity = 0
    for definition in document.definitions:
        if definition.__class__.__name__ == 'OperationDefinitionNode':
            current_depth, current_complexity = walk(definition.selection_set, 1, set())
            depth = max(depth, current_depth)
            complexity += current_complexity
    return depth, complexity


def _execute_one(payload: dict[str, Any], context: dict[str, Any], *, fixed: bool) -> dict[str, Any]:
    query = payload.get('query')
    if not isinstance(query, str) or not query.strip():
        return {'errors': [{'message': 'query required'}]}
    if fixed and ('__schema' in query or '__type' in query):
        return {'errors': [{'message': 'introspection disabled'}]}
    try:
        depth, complexity = _metrics(query)
    except Exception:
        return {'errors': [{'message': 'invalid query'}]}
    if fixed and depth > 4:
        return {'errors': [{'message': 'query depth exceeded'}]}
    if fixed and complexity > 25:
        return {'errors': [{'message': 'query complexity exceeded'}]}

    result = graphql_sync(
        SCHEMA,
        query,
        context_value=context,
        variable_values=payload.get('variables') if isinstance(payload.get('variables'), dict) else None,
        operation_name=str(payload.get('operationName') or '') or None,
    )
    response: dict[str, Any] = {'data': result.data}
    if result.errors:
        response['errors'] = [{'message': error.message} for error in result.errors]
    return response


async def _graphql_http(request: Request, vulnerable: bool):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({'errors': [{'message': 'invalid JSON'}]}, status_code=400)
    context = _context(request, vulnerable)
    if isinstance(payload, list):
        if not vulnerable:
            return JSONResponse({'errors': [{'message': 'batching disabled'}]}, status_code=400)
        return JSONResponse([
            _execute_one(item, context, fixed=False)
            for item in payload[:50]
            if isinstance(item, dict)
        ])
    if not isinstance(payload, dict):
        return JSONResponse({'errors': [{'message': 'invalid GraphQL payload'}]}, status_code=400)
    return JSONResponse(_execute_one(payload, context, fixed=not vulnerable))


@app.get('/health')
async def health():
    return {'status': 'ok'}


@app.post('/graphql')
async def graphql_fixed(request: Request):
    return await _graphql_http(request, False)


@app.post('/graphql-vulnerable')
async def graphql_vulnerable(request: Request):
    return await _graphql_http(request, True)


def _ws_identity(websocket: WebSocket) -> dict[str, str] | None:
    return _identity_from_header(websocket.headers.get('authorization'))


async def _websocket_session(
    websocket: WebSocket,
    tenant: str,
    record_id: str,
    *,
    vulnerable: bool,
):
    identity = _ws_identity(websocket)
    record = RECORDS.get(record_id)
    origin = str(websocket.headers.get('origin') or '')

    if not vulnerable:
        if origin != ALLOWED_ORIGIN:
            await websocket.close(code=4403)
            return
        if not identity or identity.get('state') != 'active':
            await websocket.close(code=4401)
            return
        if (
            record is None
            or identity.get('tenant') != tenant
            or record['tenant'] != tenant
            or (identity.get('role') != 'admin' and record['owner'] != identity.get('ref'))
        ):
            await websocket.close(code=4403)
            return

    await websocket.accept()
    count = 0
    try:
        while True:
            message = await websocket.receive()
            count += 1
            if count > 3 and not vulnerable:
                await websocket.close(code=4429)
                return
            if message.get('bytes') is not None:
                if vulnerable:
                    await websocket.send_json({'type': 'binary-accepted'})
                    continue
                await websocket.close(code=4400)
                return
            text = str(message.get('text') or '')
            if len(text.encode('utf-8')) > 1024 and not vulnerable:
                await websocket.close(code=4409)
                return
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                if vulnerable:
                    await websocket.send_json({'type': 'accepted-invalid'})
                    continue
                await websocket.close(code=4400)
                return
            if not isinstance(payload, dict) or payload.get('action') not in {'subscribe', 'ping'}:
                if vulnerable:
                    await websocket.send_json({'type': 'accepted-invalid'})
                    continue
                await websocket.close(code=4400)
                return
            if payload.get('action') == 'ping':
                await websocket.send_json({'type': 'pong'})
                continue
            requested = str(payload.get('record_id') or '')
            target = RECORDS.get(requested)
            if (
                not vulnerable
                and (
                    requested != record_id
                    or target is None
                    or target['tenant'] != identity['tenant']
                    or (identity.get('role') != 'admin' and target['owner'] != identity['ref'])
                )
            ):
                await websocket.close(code=4403)
                return
            target = target or record or {'id': requested, 'tenant': tenant, 'owner': 'unknown', 'value': 'unknown', 'secret': 'unknown'}
            await websocket.send_json({
                'type': 'event',
                'record': target if vulnerable else {
                    'id': target['id'],
                    'tenant': target['tenant'],
                    'owner': target['owner'],
                    'value': target['value'],
                },
            })
    except WebSocketDisconnect:
        return


@app.websocket('/ws/{tenant}/{record_id}')
async def ws_fixed(websocket: WebSocket, tenant: str, record_id: str):
    await _websocket_session(websocket, tenant, record_id, vulnerable=False)


@app.websocket('/ws-vulnerable/{tenant}/{record_id}')
async def ws_vulnerable(websocket: WebSocket, tenant: str, record_id: str):
    await _websocket_session(websocket, tenant, record_id, vulnerable=True)


async def _graphql_subscription(
    websocket: WebSocket,
    tenant: str,
    record_id: str,
    *,
    vulnerable: bool,
):
    identity = _ws_identity(websocket)
    origin = str(websocket.headers.get('origin') or '')
    record = RECORDS.get(record_id)
    if not vulnerable:
        if origin != ALLOWED_ORIGIN or not identity or identity.get('state') != 'active':
            await websocket.close(code=4403)
            return
        if (
            record is None
            or record['tenant'] != tenant
            or identity.get('tenant') != tenant
            or (identity.get('role') != 'admin' and record['owner'] != identity.get('ref'))
        ):
            await websocket.close(code=4403)
            return

    requested_subprotocols = websocket.headers.get('sec-websocket-protocol', '')
    subprotocol = 'graphql-transport-ws' if 'graphql-transport-ws' in requested_subprotocols else None
    await websocket.accept(subprotocol=subprotocol)
    try:
        init = json.loads(await websocket.receive_text())
        if init.get('type') != 'connection_init':
            await websocket.close(code=4400)
            return
        await websocket.send_json({'type': 'connection_ack'})
        subscribe = json.loads(await websocket.receive_text())
        payload = subscribe.get('payload') if isinstance(subscribe, dict) else {}
        query = payload.get('query') if isinstance(payload, dict) else ''
        variables = payload.get('variables') if isinstance(payload, dict) else {}
        requested = str(variables.get('id') or '') if isinstance(variables, dict) else ''
        if not isinstance(query, str) or 'subscription' not in query:
            await websocket.close(code=4400)
            return
        target = RECORDS.get(requested)
        if (
            not vulnerable
            and (
                requested != record_id
                or target is None
                or target['tenant'] != identity['tenant']
                or (identity.get('role') != 'admin' and target['owner'] != identity['ref'])
                or 'secret' in query and identity.get('role') != 'admin'
            )
        ):
            await websocket.send_json({
                'id': subscribe.get('id'),
                'type': 'error',
                'payload': [{'message': 'subscription forbidden'}],
            })
            return
        target = target or record
        await websocket.send_json({
            'id': subscribe.get('id'),
            'type': 'next',
            'payload': {'data': {'recordChanged': target}},
        })
    except (WebSocketDisconnect, json.JSONDecodeError):
        return


@app.websocket('/graphql-ws/{tenant}/{record_id}')
async def graphql_ws_fixed(websocket: WebSocket, tenant: str, record_id: str):
    await _graphql_subscription(websocket, tenant, record_id, vulnerable=False)


@app.websocket('/graphql-ws-vulnerable/{tenant}/{record_id}')
async def graphql_ws_vulnerable(websocket: WebSocket, tenant: str, record_id: str):
    await _graphql_subscription(websocket, tenant, record_id, vulnerable=True)
