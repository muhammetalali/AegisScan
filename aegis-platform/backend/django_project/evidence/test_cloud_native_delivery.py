from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan, ScanEngineExecution
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import create_credential_secret
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution
from fastapi_app.tasks.native_capabilities import run_native_capability_scan


@pytest.mark.django_db(transaction=True)
def test_cloud_vault_to_worker_to_finding_evidence_is_idempotent_and_secret_free(tmp_path: Path, monkeypatch):
    user = get_user_model().objects.create_user(email='cloud-delivery@example.test', password='CloudDelivery-123!')
    project = Project.objects.create(name='Cloud Delivery', slug='cloud-delivery', owner=user)
    target = 'aws://123456789012'
    asset = Asset.objects.create(
        project=project, name='Cloud account', slug='cloud-account', type=Asset.Type.CLOUD_RESOURCE,
        owner=user, configuration={'target': target},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset, actor=user, authorized=True, target_snapshot=target,
        reason='Authorized cloud posture reality fixture',
    )
    secret_value = 'cloud-worker-secret-never-persist'
    secret_json = json.dumps({
        'provider': 'aws', 'access_key_id': 'AKIADELIVERY', 'secret_access_key': secret_value, 'region': 'us-east-1'
    })
    credential = create_credential_secret(
        project=project, actor=user, name='cloud-readonly', kind=CredentialSecret.Kind.CLOUD_ACCESS_KEY,
        secret=secret_json, scope={'provider': 'aws', 'account_id': '123456789012'},
    )
    credential_context = authorize_credential_refs_for_execution(
        project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
        capability_id='cloud.read-only-posture', allowed_kinds=('cloud_access_key',),
        target=target,
    )
    scan = Scan.objects.create(
        project=project, asset=asset, authorization_decision=authorization, name='Cloud posture delivery',
        scan_type=Scan.Type.FULL_VALIDATION, engines=['aegis-cloud-security'], initiated_by=user,
        status=Scan.Status.QUEUED,
        config={
            'target': target,
            'capability_id': 'cloud.read-only-posture',
            'capability_options': {},
            'credential_refs': [str(credential.id)],
            'credential_context': credential_context,
        },
    )

    binary = tmp_path / 'aegis-cloud-security'
    binary.write_text(
        '#!/usr/bin/env python3\n'
        'import json, os, stat, sys\n'
        'args=sys.argv[1:]\n'
        'assert args[0] == "--credentials-file"\n'
        'p=args[1]\n'
        'assert stat.S_IMODE(os.stat(p).st_mode) == 0o600\n'
        'data=json.load(open(p, encoding="utf-8"))\n'
        'assert data["provider"] == "aws"\n'
        'target=args[2]\n'
        'result={"schema":"aegis.cloud-security.v1","provider":"aws","target":target,"observations":['
        '{"kind":"cloud-security-summary","provider":"aws","target":target,"identity_verified":True,"read_only":True,"credential_source":"vault-materialized-file","ambient_credentials_used":False,"inventory":{"account_id":"123456789012"},"coverage_gaps":[],"finding_count":1},'
        '{"kind":"cloud-security-finding","provider":"aws","rule_id":"cloud.aws.fixture-posture","title":"Fixture cloud posture violation","description":"Deterministic worker delivery proof.","severity":"high","confidence":"high","category":"cloud-security","location":"aws://fixture/resource","resource_kind":"aws.fixture","resource_name":"resource","remediation":"Apply least privilege."}'
        ']}\n'
        'print(json.dumps(result, separators=(",",":"), sort_keys=True))\n',
        encoding='utf-8',
    )
    binary.chmod(0o755)
    monkeypatch.setenv('PATH', f'{tmp_path}:{os.environ.get("PATH", "")}')
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'ambient-must-be-removed')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'ambient-secret-must-be-removed')

    first = run_native_capability_scan.run(str(scan.id))
    assert first['status'] == Scan.Status.COMPLETED
    assert first['capability_id'] == 'cloud.read-only-posture'
    assert len(first['finding_ids']) == 1
    assert CredentialAccess.objects.filter(
        credential=credential, operation=CredentialAccess.Operation.RESOLVE, result=CredentialAccess.Result.ALLOWED
    ).exists()
    assert Vulnerability.objects.filter(scan=scan, category='cloud-security').count() == 1
    assert Evidence.objects.filter(scan=scan).count() == 2
    assert ScanEngineExecution.objects.filter(scan=scan).count() == 1

    persisted = '\n'.join([
        json.dumps(scan.config, default=str),
        *[e.raw_output + json.dumps(e.metadata, default=str) for e in Evidence.objects.filter(scan=scan)],
        *[json.dumps(v.raw_data, default=str) for v in Vulnerability.objects.filter(scan=scan)],
        *[json.dumps(x.result_data, default=str) + x.error_message for x in ScanEngineExecution.objects.filter(scan=scan)],
    ])
    assert secret_value not in persisted
    assert secret_json not in persisted
    assert 'ambient-secret-must-be-removed' not in persisted

    counts = (
        Vulnerability.objects.filter(scan=scan).count(),
        Evidence.objects.filter(scan=scan).count(),
        ScanEngineExecution.objects.filter(scan=scan).count(),
    )
    second = run_native_capability_scan.run(str(scan.id))
    assert second['status'] == Scan.Status.COMPLETED
    assert counts == (
        Vulnerability.objects.filter(scan=scan).count(),
        Evidence.objects.filter(scan=scan).count(),
        ScanEngineExecution.objects.filter(scan=scan).count(),
    )
