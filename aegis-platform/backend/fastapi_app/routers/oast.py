from __future__ import annotations

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from django_project.users.models import Permission

from ..core.dependencies import get_current_user, require_permission
from ..services.governed_oast import (
    OASTRuntimeError,
    create_oast_session,
    get_oast_session,
    ingest_http_callback,
)


router = APIRouter()
_MAX_HTTP_BODY_BYTES = 16 * 1024


class OASTSessionCreate(BaseModel):
    project_id: str
    asset_id: str
    authorization_decision_id: str
    execution_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=16, max_length=128)
    target: str = Field(default='', max_length=500)
    scan_id: str | None = None
    ttl_seconds: int = Field(default=300, ge=30, le=1800)
    max_interactions: int = Field(default=8, ge=1, le=64)


def _translate(exc: OASTRuntimeError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={'code': exc.code, 'message': str(exc)},
    )


@router.post('/sessions')
async def create_session(
    payload: OASTSessionCreate,
    user=Depends(require_permission(Permission.SCAN_CREATE)),
):
    try:
        return await sync_to_async(create_oast_session)(
            user_id=str(user.get('user_id')),
            project_id=payload.project_id,
            asset_id=payload.asset_id,
            authorization_decision_id=payload.authorization_decision_id,
            execution_id=payload.execution_id,
            idempotency_key=payload.idempotency_key,
            target=payload.target,
            scan_id=payload.scan_id,
            ttl_seconds=payload.ttl_seconds,
            max_interactions=payload.max_interactions,
        )
    except OASTRuntimeError as exc:
        raise _translate(exc) from exc


@router.get('/sessions/{session_id}')
async def session_status(
    session_id: str,
    user=Depends(get_current_user),
):
    try:
        return await sync_to_async(get_oast_session)(
            session_id=session_id,
            user_id=str(user.get('user_id')),
        )
    except OASTRuntimeError as exc:
        raise _translate(exc) from exc


async def _bounded_body(request: Request) -> bytes:
    declared = request.headers.get('content-length')
    if declared:
        try:
            if int(declared) > _MAX_HTTP_BODY_BYTES:
                raise HTTPException(status_code=413, detail='OAST callback payload is too large')
        except ValueError as exc:
            raise HTTPException(status_code=400, detail='Invalid Content-Length') from exc
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_HTTP_BODY_BYTES:
            raise HTTPException(status_code=413, detail='OAST callback payload is too large')
    return bytes(body)


@router.api_route(
    '/callback/{session_id}/{token}',
    methods=['GET', 'HEAD', 'POST'],
    include_in_schema=False,
)
async def http_callback(
    session_id: str,
    token: str,
    request: Request,
):
    body = await _bounded_body(request) if request.method == 'POST' else b''
    source_ip = request.client.host if request.client else None
    query = (request.scope.get('query_string') or b'').decode('utf-8', errors='replace')
    try:
        await sync_to_async(ingest_http_callback)(
            session_id=session_id,
            token=token,
            source_ip=source_ip,
            method=request.method,
            query_string=query,
            headers=dict(request.headers),
            body=body,
        )
    except OASTRuntimeError as exc:
        raise _translate(exc) from exc
    return Response(status_code=204)
