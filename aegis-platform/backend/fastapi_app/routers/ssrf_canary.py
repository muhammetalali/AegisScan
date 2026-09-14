from __future__ import annotations

import hashlib
import hmac
import os
import re

import redis
from fastapi import APIRouter, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict

from fastapi_app.core.config import settings

router = APIRouter()
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')
_CONTROL_RE = re.compile(r'^[a-f0-9]{64}$')
_TTL_SECONDS = 300
_PREFIX = 'aegis:ssrf-canary:'


class CanaryRegistration(BaseModel):
    model_config = ConfigDict(extra='forbid')
    token: str


def _control_token() -> str:
    token = os.getenv('AEGIS_SSRF_CANARY_CONTROL_TOKEN', '').strip()
    if not _CONTROL_RE.fullmatch(token):
        raise HTTPException(status_code=503, detail='SSRF canary control is not configured')
    return token


def _require_control(value: str | None) -> None:
    expected = _control_token()
    if not hmac.compare_digest(value or '', expected):
        raise HTTPException(status_code=403, detail='SSRF canary control authorization failed')


def _token_digest(token: str) -> str:
    if not _TOKEN_RE.fullmatch(token):
        raise HTTPException(status_code=404, detail='SSRF canary token not found')
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def _client():
    return redis.from_url(
        settings.REDIS_URL,
        socket_connect_timeout=3,
        socket_timeout=3,
        decode_responses=True,
    )


@router.post('/register')
def register_canary(
    payload: CanaryRegistration,
    x_aegis_canary_control: str | None = Header(default=None),
):
    _require_control(x_aegis_canary_control)
    digest = _token_digest(payload.token)
    pending = _PREFIX + 'pending:' + digest
    observed = _PREFIX + 'observed:' + digest
    client = _client()
    try:
        client.delete(observed)
        created = client.set(pending, '1', ex=_TTL_SECONDS, nx=True)
    finally:
        client.close()
    if not created:
        raise HTTPException(status_code=409, detail='SSRF canary token already registered')
    return {'status': 'registered', 'expires_in_seconds': _TTL_SECONDS}


@router.get('/callback/{token}', include_in_schema=False)
def callback(token: str):
    digest = _token_digest(token)
    pending = _PREFIX + 'pending:' + digest
    observed = _PREFIX + 'observed:' + digest
    client = _client()
    try:
        if client.exists(pending) != 1:
            raise HTTPException(status_code=404, detail='SSRF canary token not found')
        client.set(observed, '1', ex=_TTL_SECONDS)
    finally:
        client.close()
    return Response(content='ok\n', media_type='text/plain', status_code=200)


@router.get('/status/{token}')
def canary_status(
    token: str,
    x_aegis_canary_control: str | None = Header(default=None),
):
    _require_control(x_aegis_canary_control)
    digest = _token_digest(token)
    pending = _PREFIX + 'pending:' + digest
    observed = _PREFIX + 'observed:' + digest
    client = _client()
    try:
        exists = client.exists(pending) == 1
        seen = client.exists(observed) == 1
        ttl = client.ttl(pending)
    finally:
        client.close()
    if not exists:
        raise HTTPException(status_code=404, detail='SSRF canary token not found')
    return {
        'status': 'registered',
        'observed': seen,
        'expires_in_seconds': max(0, int(ttl)),
    }
