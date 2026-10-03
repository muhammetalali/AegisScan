"""Optional isolated P3 acceptance harness; governance/auth fixtures are synthetic.

Run from the embedded scanner image with a dedicated PostgreSQL/Redis pair.
This deliberately refuses production database and broker destinations. It does
not certify vendor licensing, signatures, SBOM, live fixture binding or a verdict.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['schedule', 'collect'])
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    database = urlsplit(os.environ.get('DATABASE_URL', ''))
    broker = urlsplit(os.environ.get('CELERY_BROKER_URL', ''))
    if (database.hostname != 'aegis-burp-p3-postgres' or database.path != '/burp_p3'
            or broker.hostname != 'aegis-burp-p3-redis'
            or os.environ.get('AEGIS_ISOLATED_BURP_LAB_PROOF') != '1'):
        raise SystemExit('This harness requires the dedicated isolated P3 database and broker.')
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
    import django
    django.setup()
    from asgiref.sync import sync_to_async
    from django.db import connections
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from django_project.assets.models import Asset, AssetAuthorization
    from django_project.evidence.models import Evidence
    from django_project.projects.models import Project
    from django_project.scans.models import Scan, ScanLog
    from django_project.system.credential_models import CredentialSecret
    from django_project.system.credential_vault import encrypt_secret, credential_fingerprint
    from django_project.users.models import User
    from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPInvocationClaim
    from enterprise.models import Organization, OrganizationMembership, TenantProject
    from enterprise.provider_approval_models import ProviderApprovalDecision
    from fastapi_app.core.dependencies import get_current_user
    from fastapi_app.routers.capabilities import router
    from fastapi_app.services.burp_lab_requests import STEPS
    from fastapi_app.services.burp_mcp_gateway import invoke_burp_mcp
    from fastapi_app.services.web_security_foundation import persist_provider_approval

    if args.action == 'schedule':
        if args.state.exists():
            raise SystemExit('Existing attempt state must be reconciled, not overwritten.')
        marker = uuid4().hex[:12]
        user = User.objects.create_user(email=f'isolated-p3-{marker}@example.invalid', password=None)
        project = Project.objects.create(name='Isolated P3 acceptance', slug='p3-' + marker, owner=user)
        asset = Asset.objects.create(project=project, name='Pinned BAC fixture', slug='fixture-' + marker,
            type=Asset.Type.WEBSITE, configuration={'url': 'http://127.0.0.1:18081', 'authorized': True})
        authorization = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True,
            target_snapshot='http://127.0.0.1:18081')
        org = Organization.objects.create(name='Isolated P3 tenant', slug='p3-' + marker, owner=user)
        OrganizationMembership.objects.create(organization=org, user=user, is_active=True,
            role=OrganizationMembership.Role.MANAGER)
        TenantProject.objects.create(organization=org, project=project)
        refs = []
        for identity in ('alice', 'bob'):
            token = identity + '-token'
            credential = CredentialSecret.objects.create(project=project, created_by=user,
                name=identity, kind=CredentialSecret.Kind.TOKEN, encrypted_secret=encrypt_secret(token),
                secret_fingerprint=credential_fingerprint(token),
                scope={'browser_origin': 'http://127.0.0.1:18081', 'browser_identity_ref': identity})
            refs.append(str(credential.id))
        # These acceptance fixtures exercise the approval gate; they are NOT
        # vendor attestations, and must never be used to approve production.
        manifest = {'license': 'synthetic-acceptance-fixture', 'maintenance': {'status': 'active'},
            'sbom': True, 'supply_chain_integrity': True, 'sbom_sha256': 'a' * 64,
            'provenance_sha256': 'b' * 64, 'artifact_sha256': 'c' * 64,
            'signature_identity': 'synthetic-test-fixture:not-vendor-signature', 'signature_verified': True,
            'known_cves': [], 'container_privileges': [], 'network_permissions': ['authorized-target-only'],
            'output_quality': {'schema': 'mcp-jsonrpc-2.0', 'bounded': True}, 'determinism': True,
            'evidence_quality': True, 'ci_reproducibility': True, 'unmitigated_critical_cves': [],
            'approval_metadata_synthetic': True, 'mcp_endpoint': 'http://127.0.0.1:9876/',
            'mcp_transport': 'sse', 'mcp_tools': {'burp.http_request': 'send_http1_request'},
            'mcp_tool_schema_sha256': '337bfce281301e755dfd4422c79c32c18e672e5b9c492b7974b47777791434e9'}
        persist_provider_approval(project, str(user.id), {'provider_name': 'burp-suite-mcp',
            'provider_version': '2026.9', 'status': 'approved', 'capability': 'burp.mcp.gateway',
            'manifest': manifest, 'rationale': 'Isolated integration fixture; no vendor or production trust claim.'})
        decision = ProviderApprovalDecision.objects.filter(project=project).latest('decision_version')
        body = {'project_id': str(project.id), 'asset_id': str(asset.id), 'credential_refs': refs,
            'options': {'provider_decision_ref': str(decision.id), 'mode': 'lab_sequence'},
            'idempotency_key': 'live-p3-' + marker, 'correlation_id': 'live-p3-' + marker}
    else:
        state = json.loads(args.state.read_text())
        body, user = state['body'], User.objects.get(pk=state['actor_ref'])
    app = FastAPI()
    app.include_router(router, prefix='/api/v1/capabilities')
    # The authenticated principal is a synthetic fixture, not a production login test.
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(user.id)}
    with TestClient(app) as client:
        response = client.post('/api/v1/capabilities/burp.mcp.gateway/execute', json=body)
        if response.status_code != 202:
            raise RuntimeError(f'Canonical scheduling rejected the fixture: HTTP {response.status_code}')
        result = response.json()
        scan = Scan.objects.get(pk=result['scan']['id'])
        if args.action == 'schedule':
            args.state.write_text(json.dumps({'body': body, 'actor_ref': str(user.id), 'scan_ref': str(scan.id)}))
            print(json.dumps({'status': 'scheduled', 'scan_ref': str(scan.id), 'queue': 'scanners',
                              'approval_metadata_synthetic': True, 'authenticated_principal_synthetic': True}))
            return 0
        if scan.status != Scan.Status.COMPLETED:
            print(json.dumps({'status': scan.status, 'error_type': scan.engine_results.get('burp-mcp', {}).get('error_type')}))
            return 2
        assert result['idempotency_reused'] is True
        invocations = list(BurpMCPInvocation.objects.filter(session__scan=scan).order_by('invocation_sequence'))
        claims = list(BurpMCPInvocationClaim.objects.filter(session__scan=scan))
        observations = scan.engine_results['burp-mcp']['observations']
        assert len(invocations) == len(claims) == len(observations) == 6
        assert all(c.state == 'committed' for c in claims)
        assert all(i.qualification.qualified for i in invocations)
        assert [o['step_ref'] for o in observations] == list(STEPS)
        assert [o['status_code'] for o in observations] == [200, 200, 404, 200, 401, 200]
        assert [o['identity_ref'] for o in observations] == ['alice', 'alice', 'alice', 'bob', 'anonymous', 'alice']
        assert observations[0]['resource']['owner_id'] == observations[-1]['resource']['owner_id'] == 'alice'
        assert observations[1]['resource']['owner_id'] == observations[3]['resource']['owner_id'] == 'bob'
        for i in invocations:
            replay = invoke_burp_mcp(session_id=str(i.session_id), actor_id=str(user.id),
                operation='burp.http_request', arguments={'lab_step': i.result_summary['step_ref']},
                idempotency_key=i.idempotency_key)
            assert replay.replayed and replay.invocation.id == i.id
        persisted = json.dumps(scan.engine_results) + ''.join(Evidence.objects.filter(scan=scan).values_list('raw_output', flat=True))
        persisted += json.dumps(list(ScanLog.objects.filter(scan=scan).values_list('context', flat=True)))
        assert all(s not in persisted for s in ['alice-token', 'bob-token', 'Authorization:', 'Set-Cookie'])
        assert BurpMCPInvocationClaim.objects.filter(session__scan=scan).count() == 6
        proof = {'schema': 'aegis.burp-live-recipe-proof.v1', 'status': 'pass', 'scan_ref': str(scan.id),
            'source_commit': os.environ['AEGIS_PROOF_SOURCE_COMMIT'], 'canonical_route_and_real_broker': True,
            'worker_queue': 'scanners', 'approval_metadata_synthetic': True, 'authenticated_principal_synthetic': True,
            'provider_production_admissibility_verified': False, 'observations': observations,
            'evidence_refs': [str(i.evidence_id) for i in invocations], 'qualified_evidence_count': 6,
            'committed_key_reconciliation_without_new_claim': True, 'raw_request_response_persisted': False,
            'lab_solved': False, 'live_fixture_revision_verified': False}
        args.state.with_name('live-recipe-proof.json').write_text(json.dumps(proof, indent=2))
        client.portal.call(sync_to_async(connections.close_all, thread_sensitive=True))
        print(json.dumps(proof))
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
