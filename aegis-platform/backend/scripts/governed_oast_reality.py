from __future__ import annotations

import json
import os
import socket
import struct
from datetime import timedelta
from threading import Thread
from urllib.parse import urlsplit

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

import django

django.setup()

from django.utils import timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import GovernedOASTInteraction, GovernedOASTSession
from django_project.projects.models import Project
from django_project.users.models import User, UserRole

from fastapi_app.core.dependencies import get_current_user
from fastapi_app.routers import oast
from fastapi_app.services import wstg_native_capabilities as wstg
from fastapi_app.services.oast_dns_collector import start_dns_collector


def _dns_query(name: str, query_id: int = 0xA501) -> bytes:
    question = b''.join(
        bytes([len(label)]) + label.encode('ascii')
        for label in name.rstrip('.').split('.')
    ) + b'\x00' + struct.pack('!HH', 1, 1)
    return struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question


def main() -> int:
    os.environ['OAST_TOKEN_SIGNING_KEY'] = 'reality-oast-signing-key-' + ('r' * 48)
    os.environ['OAST_PUBLIC_HTTP_BASE'] = 'http://localhost/api/v1/oast/callback'
    os.environ['OAST_PUBLIC_DNS_DOMAIN'] = 'callbacks.oast.test'
    os.environ['OAST_ALLOW_INSECURE_LOCAL'] = 'true'
    os.environ['AUTHORIZED_SCAN_TARGETS'] = '127.0.0.1/32'

    user = User.objects.create_user(
        email='oast-reality@example.test',
        password='unused',
        first_name='OAST',
        last_name='Reality',
        role=UserRole.SECURITY_ANALYST,
    )
    project = Project.objects.create(
        name='OAST Reality',
        slug=f'oast-reality-{str(user.id)[:8]}',
        owner=user,
    )
    target = 'http://127.0.0.1:18080/'
    asset = Asset.objects.create(
        project=project,
        name='OAST Reality Target',
        slug='oast-reality-target',
        type=Asset.Type.WEBSITE,
        configuration={'url': target},
        owner=user,
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=target,
        reason='governed OAST runtime reality',
        expires_at=timezone.now() + timedelta(minutes=30),
    )

    app = FastAPI()
    app.include_router(oast.router, prefix='/api/v1/oast')
    app.dependency_overrides[get_current_user] = lambda: {
        'user_id': str(user.id),
        'is_staff': False,
    }
    client = TestClient(app)

    create_response = client.post(
        '/api/v1/oast/sessions',
        json={
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'authorization_decision_id': str(authorization.id),
            'execution_id': 'reality-execution-1',
            'idempotency_key': 'governed-oast-reality-0001',
            'target': target,
            'ttl_seconds': 300,
            'max_interactions': 8,
        },
    )
    assert create_response.status_code == 200, create_response.text
    session_payload = create_response.json()
    session_id = session_payload['id']
    callback_url = session_payload['callbacks']['http_url']
    callback_path = urlsplit(callback_url).path
    callback_token = callback_path.rstrip('/').split('/')[-1]

    http_response = client.get(
        callback_path + '?probe=reality',
        headers={
            'User-Agent': 'Aegis-OAST-Reality/1.0',
            'Authorization': 'fixture-must-not-persist',
        },
    )
    assert http_response.status_code == 204, http_response.text
    duplicate_response = client.get(
        callback_path + '?probe=reality',
        headers={
            'User-Agent': 'Aegis-OAST-Reality/1.0',
            'Authorization': 'fixture-must-not-persist',
        },
    )
    assert duplicate_response.status_code == 204, duplicate_response.text

    dns_server = start_dns_collector('127.0.0.1', 0)
    dns_thread = Thread(target=dns_server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    dns_thread.start()
    try:
        packet = _dns_query(session_payload['callbacks']['dns_name'])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(packet, dns_server.server_address)
            response, _ = sock.recvfrom(2048)
        assert len(response) >= 12
        _query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
        assert flags & 0x8000
        assert flags & 0x000F == 3
        assert (qdcount, ancount, nscount, arcount) == (1, 0, 0, 0)
    finally:
        dns_server.shutdown()
        dns_server.server_close()
        dns_thread.join(timeout=2)

    assert len(dns_server.accepted_events) == 1
    interactions = list(
        GovernedOASTInteraction.objects.filter(session_id=session_id)
        .select_related('evidence')
        .order_by('observed_at')
    )
    assert len(interactions) == 2
    assert {item.protocol for item in interactions} == {'http', 'dns'}
    assert all(item.evidence.sha256 for item in interactions)
    assert all(item.evidence.metadata.get('authoritative_oast_evidence') is True for item in interactions)
    assert all(callback_token not in item.evidence.raw_output for item in interactions)
    assert all('fixture-must-not-persist' not in item.evidence.raw_output for item in interactions)

    result = wstg.run_wstg_internal_capability(
        'web.ssrf-canary-validation',
        target,
        {
            'oast_session_id': session_id,
            'execution_id': 'reality-execution-1',
        },
    )
    raw = json.loads(result.stdout)
    observation = raw['observations'][0]
    assert observation['ssrf_confirmed'] is True
    assert observation['callback_observed'] is True
    assert observation['authoritative_oast_evidence'] is True
    assert observation['callback_attempted'] is False
    assert observation['final_decision'] is False
    assert set(observation['protocols']) == {'http', 'dns'}

    normalized = wstg.normalize_wstg_internal_output(
        'web.ssrf-canary-validation',
        result.stdout,
    )
    normalized_observation = normalized['observations'][0]
    assert normalized_observation['ssrf_confirmed'] is True
    assert normalized_observation['authoritative_oast_evidence'] is True

    session = GovernedOASTSession.objects.get(pk=session_id)
    report = {
        'schema': 'aegis.governed-oast-runtime-reality.v1',
        'session_id': str(session.id),
        'project_id': str(project.id),
        'asset_id': str(asset.id),
        'authorization_decision_id': str(authorization.id),
        'execution_id': session.execution_id,
        'session_token_persisted_raw': False,
        'http_callback': 'proven',
        'dns_callback': 'proven',
        'duplicate_http_persisted_count': GovernedOASTInteraction.objects.filter(
            session=session,
            protocol='http',
        ).count(),
        'interaction_count': len(interactions),
        'protocols': sorted({item.protocol for item in interactions}),
        'evidence_sha256': [item.evidence.sha256 for item in interactions],
        'wstg_inpv_19_runtime': 'authoritative-oast-evidence-proven',
        'methodology_cutover_performed': False,
    }
    serialized = json.dumps(report, sort_keys=True, separators=(',', ':'))
    assert callback_token not in serialized
    print(serialized)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
