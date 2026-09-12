from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Response

app = FastAPI(title='AegisScan BAC Reality Fixture', version='1.0.0')

IDENTITIES = {
    'alice-token': {'ref': 'alice', 'tenant': 'tenant-a', 'role': 'viewer'},
    'bob-token': {'ref': 'bob', 'tenant': 'tenant-b', 'role': 'viewer'},
    'admin-token': {'ref': 'admin-a', 'tenant': 'tenant-a', 'role': 'admin'},
}
ORDERS = {
    '51': {'id': '51', 'owner_id': 'alice', 'tenant_id': 'tenant-a', 'amount': 125},
    '74': {'id': '74', 'owner_id': 'bob', 'tenant_id': 'tenant-b', 'amount': 900},
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
    return {'status': 'ok', 'fixture': 'bac-target'}


@app.get('/fixed/orders/{order_id}')
def fixed_order(order_id: str, response: Response, authorization: str | None = Header(default=None)):
    identity = _identity(authorization)
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail='Not found')
    if order['tenant_id'] != identity['tenant'] or order['owner_id'] != identity['ref']:
        raise HTTPException(status_code=404, detail='Not found')
    _secure_headers(response)
    return order


@app.get('/vulnerable/orders/{order_id}')
def vulnerable_order(order_id: str, response: Response, authorization: str | None = Header(default=None)):
    _identity(authorization)
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail='Not found')
    _secure_headers(response)
    return order


@app.delete('/fixed/orders/{order_id}')
def fixed_delete(order_id: str, response: Response, authorization: str | None = Header(default=None)):
    identity = _identity(authorization)
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail='Not found')
    if identity['role'] != 'admin' or identity['tenant'] != order['tenant_id']:
        raise HTTPException(status_code=403, detail='Forbidden')
    _secure_headers(response)
    return {'deleted': order_id, 'fixture_only': True}


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=int(os.getenv('PORT', '18081')), log_level='warning')
