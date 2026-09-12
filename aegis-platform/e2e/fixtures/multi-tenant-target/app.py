from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Response

app = FastAPI(title='AegisScan Multi-Tenant Reality Fixture', version='1.0.0')

IDENTITIES = {
    'tenant-a-token': {'ref': 'service-a', 'tenant': 'tenant-a', 'role': 'viewer'},
    'tenant-b-token': {'ref': 'service-b', 'tenant': 'tenant-b', 'role': 'viewer'},
}
RECORDS = {
    'alpha': {'id': 'alpha', 'tenant_id': 'tenant-a', 'classification': 'private', 'value': 'tenant-a-value'},
    'bravo': {'id': 'bravo', 'tenant_id': 'tenant-b', 'classification': 'private', 'value': 'tenant-b-value'},
}


def _identity(authorization: str | None) -> dict:
    prefix = 'Bearer '
    if not authorization or not authorization.startswith(prefix):
        raise HTTPException(status_code=401, detail='Authentication required')
    identity = IDENTITIES.get(authorization[len(prefix):])
    if identity is None:
        raise HTTPException(status_code=401, detail='Invalid token')
    return identity


def _secure_headers(response: Response) -> None:
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'


@app.get('/health')
def health(response: Response):
    _secure_headers(response)
    return {'status': 'ok', 'fixture': 'multi-tenant-target'}


@app.get('/fixed/tenants/{tenant_ref}/records/{record_id}')
def fixed_record(
    tenant_ref: str,
    record_id: str,
    response: Response,
    authorization: str | None = Header(default=None),
):
    identity = _identity(authorization)
    record = RECORDS.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail='Not found')
    if identity['tenant'] != tenant_ref or record['tenant_id'] != tenant_ref:
        raise HTTPException(status_code=404, detail='Not found')
    _secure_headers(response)
    return record


@app.get('/vulnerable/tenants/{tenant_ref}/records/{record_id}')
def vulnerable_record(
    tenant_ref: str,
    record_id: str,
    response: Response,
    authorization: str | None = Header(default=None),
):
    _identity(authorization)
    record = RECORDS.get(record_id)
    if record is None or record['tenant_id'] != tenant_ref:
        raise HTTPException(status_code=404, detail='Not found')
    _secure_headers(response)
    return record


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=int(os.getenv('PORT', '18082')), log_level='warning')
