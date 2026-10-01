from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import urllib.error
import urllib.request
from collections.abc import Iterable


class DynamicEgressError(RuntimeError):
    pass


def _token() -> str:
    root = os.getenv('AEGIS_SCANNER_EGRESS_CONTROL_ROOT', '').strip()
    if not root:
        return ''
    return hmac.new(
        root.encode('utf-8'),
        b'aegisscan-scanner-egress-control-v1',
        hashlib.sha256,
    ).hexdigest()


def _endpoint() -> str:
    return os.getenv('AEGIS_SCANNER_EGRESS_CONTROL_URL', '').strip().rstrip('/')


def _non_global_network(value: str) -> str | None:
    raw = str(value).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        return str(address) if not address.is_global else None
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    if network.version == 4:
        if network.network_address.is_global and network.broadcast_address.is_global:
            return None
    elif network.network_address.is_global:
        return None
    return str(network)


def authorize_dynamic_egress(destinations: Iterable[str]) -> None:
    private_targets = [
        normalized
        for destination in destinations
        if (normalized := _non_global_network(str(destination))) is not None
    ]
    if not private_targets:
        return
    endpoint = _endpoint()
    # Dynamic admission is a deployment feature. Runtimes that do not opt in
    # continue to rely on the already-enforced governed/static scope boundary.
    # Production scanner/browser workers explicitly configure this localhost
    # endpoint, so a missing control root there still fails closed.
    if not endpoint:
        return
    if endpoint != 'http://127.0.0.1:18780':
        raise DynamicEgressError('Dynamic egress control endpoint must remain on 127.0.0.1:18780')
    token = _token()
    if not token:
        raise DynamicEgressError(
            'Dynamic private-target egress requires AEGIS_SCANNER_EGRESS_CONTROL_ROOT'
        )

    for normalized in private_targets:
        body = json.dumps({'target': normalized}, sort_keys=True).encode('utf-8')
        request = urllib.request.Request(
            endpoint + '/v1/allow',
            data=body,
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Aegis-Egress-Token': token,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                payload = json.loads(response.read(8192).decode('utf-8'))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise DynamicEgressError(f'Dynamic scanner egress authorization failed: {exc}') from exc
        if payload.get('status') != 'ok' or payload.get('target') != normalized:
            raise DynamicEgressError('Dynamic scanner egress controller returned an invalid acknowledgement')
