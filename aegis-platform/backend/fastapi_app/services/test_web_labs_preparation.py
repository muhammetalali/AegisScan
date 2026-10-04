from __future__ import annotations

import hashlib
import json
import re
import socket
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from celery.app.task import Task
from django.db import connection, connections
from django.db.backends.utils import CursorWrapper
from django.utils import timezone
from fastapi import FastAPI
from fastapi.testclient import TestClient
from asgiref.sync import sync_to_async

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project, ProjectMembership
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system import credential_vault
from django_project.users.models import User
from enterprise.models import Organization, OrganizationMembership, TenantProject
from enterprise.provider_approval_models import ProviderApprovalDecision
from enterprise.web_security_models import ProviderApprovalRecord
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.routers.web_labs import CredentialOptionsOut, router, PrepareWebLabOut
from fastapi_app.services import burp_mcp_gateway, web_labs_preparation as preparation
from fastapi_app.services.provider_approval import record_provider_decision
from fastapi_app.services.test_burp_mcp_gateway import _manifest
from fastapi_app.services.web_security_foundation import persist_provider_approval


pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def context():
    user = User.objects.create_user(email='web-labs-owner@example.invalid', password='test-only')
    project = Project.objects.create(name='Web Labs Preview', slug='web-labs-preview', owner=user)
    asset = Asset.objects.create(project=project, name='BAC Fixture', slug='bac-fixture',
                                 type=Asset.Type.WEBSITE,
                                 configuration={'url': 'http://bac-target:18081', 'authorized': True})
    auth = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True,
                                             target_snapshot='http://bac-target:18081')
    org = Organization.objects.create(name='Preview Tenant', slug='preview-tenant', owner=user)
    membership = OrganizationMembership.objects.create(organization=org, user=user, is_active=True,
                                                         role=OrganizationMembership.Role.MANAGER)
    TenantProject.objects.create(organization=org, project=project)
    credentials = [CredentialSecret.objects.create(
        project=project, created_by=user, name=identity, kind=CredentialSecret.Kind.TOKEN,
        encrypted_secret='ciphertext-must-not-be-read', secret_fingerprint='f' * 64,
        scope={'browser_origin': 'http://bac-target:18081', 'browser_identity_ref': identity,
               'arbitrary_private_metadata': 'must-not-be-returned'},
    ) for identity in ['alice', 'bob']]
    return user, project, asset, auth, membership, credentials


def preview(context, **overrides):
    user, project, asset, _auth, _membership, credentials = context
    arguments = dict(actor_id=str(user.id), project_id=str(project.id), asset_id=str(asset.id),
                     lab_definition_id='bac-orders-v1', credential_refs=[str(c.id) for c in credentials],
                     depth='standard')
    arguments.update(overrides)
    return preparation.prepare_web_lab(**arguments)


def approve(context, *, manifest=None, name='burp-suite-mcp'):
    user, project, *_ = context
    record, _ = persist_provider_approval(project, str(user.id), {
        'provider_name': name, 'provider_version': '2026.9', 'status': 'approved',
        'capability': burp_mcp_gateway.BURP_MCP_CAPABILITY_ID,
        'manifest': manifest if manifest is not None else _manifest('https://burp-preview.invalid/mcp'),
        'rationale': 'Read-only preview test provider; no network endpoint used.',
    })
    return record


def codes(result):
    return {b['code'] for b in result['blockers']}


def test_missing_provider_is_explicit_and_no_solver_success(context):
    result = PrepareWebLabOut.model_validate(preview(context)).model_dump()
    assert result['provider']['state'] == 'missing'
    assert 'provider.missing' in codes(result)
    assert result['execution_ready'] is False
    assert result['metadata_ready'] is False
    assert result['supported_operations'] == []
    assert result['methodology_refs'] == ['WSTG-v42-ATHZ-04']
    assert all(b['message_ar'] and b['suggested_action_ar'] for b in result['blockers'])


def test_approved_provider_is_metadata_only_not_runtime_readiness(context):
    approve(context)
    result = preview(context)
    assert result['metadata_ready'] is True
    assert result['execution_ready'] is False
    assert set(result['supported_operations']) == set(_manifest('https://unused.invalid')['mcp_tools'])
    assert {'request_operation.unsupported',
            'fixture_binding.not_verified', 'runtime.not_checked'} <= codes(result)
    assert result['capabilities'][0]['registered'] is True
    assert result['capabilities'][0]['runtime_verified'] is False


@pytest.mark.parametrize('state', ['expired', 'revoked', 'binding_mismatch', 'projection_disabled'])
def test_latest_authorization_cannot_fall_back_to_previous_grant(context, state):
    user, _project, asset, old, *_ = context
    if state == 'projection_disabled':
        asset.configuration['authorized'] = False
        asset.save(update_fields=['configuration'])
    else:
        AssetAuthorization.objects.create(
            asset=asset, actor=user, authorized=state != 'revoked', supersedes=old,
            target_snapshot='http://changed.invalid' if state == 'binding_mismatch' else old.target_snapshot,
            expires_at=timezone.now() - timedelta(seconds=1) if state == 'expired' else None,
        )
    result = preview(context)
    assert f'authorization.{state}' in codes(result)
    assert result['metadata_ready'] is False


def test_cross_project_asset_and_outsider_are_indistinguishably_unavailable(context):
    user, *_ = context
    other = Project.objects.create(name='Other', slug='other-preview', owner=user)
    outsider = User.objects.create_user(email='preview-outsider@example.invalid', password='test-only')
    for overrides in [{'project_id': str(other.id)}, {'actor_id': str(outsider.id)}, {'asset_id': str(uuid4())}]:
        with pytest.raises(preparation.WebLabsAccessError, match='غير متاح'):
            preview(context, **overrides)


def test_member_access_reuses_existing_membership(context):
    _user, project, _asset, _auth, membership, _credentials = context
    member = User.objects.create_user(email='preview-member@example.invalid', password='test-only')
    ProjectMembership.objects.create(project=project, user=member)
    OrganizationMembership.objects.create(organization=membership.organization, user=member, is_active=True)
    assert preview(context, actor_id=str(member.id))['project_ref'] == str(project.id)


def test_inactive_tenant_membership_hides_provider_and_credential_metadata(context):
    approve(context)
    membership = context[4]
    membership.is_active = False
    membership.save(update_fields=['is_active'])
    result = preview(context)
    assert 'tenant.unavailable' in codes(result)
    assert result['credential_metadata'] == []
    assert result['provider']['decision_ref'] is None


@pytest.mark.parametrize('change', ['revoked', 'wrong_origin', 'wrong_identity', 'wrong_kind', 'foreign_project'])
def test_credential_metadata_rejects_invalid_bindings_without_secret_access(context, change):
    credential = context[-1][0]
    if change == 'revoked':
        credential.status = 'revoked'
    elif change == 'wrong_kind':
        credential.kind = 'password'
    elif change == 'foreign_project':
        credential.project = Project.objects.create(name='Foreign', slug='foreign-credential', owner=context[0])
    else:
        credential.scope['browser_origin' if change == 'wrong_origin' else 'browser_identity_ref'] = 'wrong'
    credential.save()
    result = preview(context)
    assert 'credentials.incomplete_or_invalid' in codes(result)
    assert 'ciphertext-must-not-be-read' not in json.dumps(result)
    assert 'must-not-be-returned' not in json.dumps(result)
    if change == 'foreign_project':
        assert result['credential_metadata'][0]['state'] == 'unavailable'


def test_latest_provider_revocation_blocks_and_multiple_providers_are_ambiguous(context):
    record = approve(context)
    record_provider_decision(project_id=str(context[1].id), actor_id=str(context[0].id),
                             provider_name=record.provider_name, provider_version=record.provider_version,
                             capability=record.capability, status='revoked', manifest=record.manifest,
                             rationale='Latest decision revokes preview provider.', legacy_approval=record)
    assert preview(context)['provider']['state'] == 'inadmissible'
    approve(context, name='second-burp-provider')
    assert preview(context)['provider']['state'] == 'ambiguous'


@pytest.mark.parametrize('bad', ['tool', 'endpoint'])
def test_provider_mapping_and_endpoint_must_match_gateway_policy(context, bad):
    manifest = _manifest('https://burp-preview.invalid/mcp')
    if bad == 'tool':
        manifest['mcp_tools']['burp.http_request'] = 'send_request'
    else:
        manifest['mcp_endpoint'] = 'https://[broken'
    approve(context, manifest=manifest)
    assert preview(context)['provider']['state'] == ('invalid_tool_mapping' if bad == 'tool' else 'invalid_endpoint')


def test_preview_issues_no_writes_secret_resolution_target_network_or_dispatch(context, monkeypatch):
    approve(context)
    before = CredentialAccess.objects.count()
    queries = []

    def guard(execute, sql, params, many, call_context):
        assert not re.search(r'\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|TRUNCATE)\b', sql, re.I), sql
        if 'system_credentialsecret' in sql.lower():
            assert 'encrypted_secret' not in sql and 'secret_fingerprint' not in sql
        queries.append(sql)
        return execute(sql, params, many, call_context)

    def forbidden(*args, **kwargs):
        raise AssertionError('Readiness preview attempted a side effect')

    for owner, name in [(credential_vault, 'decrypt_secret'), (credential_vault, 'resolve_credential_secret'),
                        (Task, 'apply_async'), (Task, 'delay'), (httpx.Client, 'request'),
                        (burp_mcp_gateway, '_perform_mcp_call'), (socket, 'getaddrinfo')]:
        monkeypatch.setattr(owner, name, forbidden)
    with connection.execute_wrapper(guard):
        first, second = preview(context), preview(context)
    assert first == second
    assert queries
    assert CredentialAccess.objects.count() == before


def test_credential_options_expose_only_safe_bound_metadata(context):
    user, project, asset, _auth, _membership, credentials = context
    payload = preparation.list_web_lab_credential_options(
        actor_id=str(user.id),
        project_id=str(project.id),
        asset_id=str(asset.id),
        lab_definition_id='bac-orders-v1',
    )
    parsed = CredentialOptionsOut.model_validate(payload).model_dump()
    assert parsed['identity_refs'] == ['alice', 'bob']
    assert [item['identity_ref'] for item in parsed['options']] == ['alice', 'bob']
    assert [item['credential_ref'] for item in parsed['options']] == [str(c.id) for c in credentials]
    serialized = json.dumps(parsed)
    assert 'ciphertext-must-not-be-read' not in serialized
    assert 'secret_fingerprint' not in serialized
    assert 'arbitrary_private_metadata' not in serialized
    assert 'browser_origin' not in serialized


def test_credential_options_require_active_tenant_membership(context):
    user, project, asset, _auth, membership, _credentials = context
    membership.is_active = False
    membership.save(update_fields=['is_active'])
    with pytest.raises(preparation.WebLabsAccessError, match='غير متاح'):
        preparation.list_web_lab_credential_options(
            actor_id=str(user.id),
            project_id=str(project.id),
            asset_id=str(asset.id),
            lab_definition_id='bac-orders-v1',
        )


def test_credential_options_exclude_wrong_origin_and_foreign_scope(context):
    user, project, asset, _auth, _membership, credentials = context
    credentials[0].scope['browser_origin'] = 'https://wrong.invalid'
    credentials[0].save(update_fields=['scope'])
    foreign = Project.objects.create(name='Foreign options', slug='foreign-options', owner=user)
    CredentialSecret.objects.create(
        project=foreign, created_by=user, name='foreign-alice', kind=CredentialSecret.Kind.TOKEN,
        encrypted_secret='foreign-ciphertext', secret_fingerprint='e' * 64,
        scope={'browser_origin': 'http://bac-target:18081', 'browser_identity_ref': 'alice'},
    )
    payload = preparation.list_web_lab_credential_options(
        actor_id=str(user.id),
        project_id=str(project.id),
        asset_id=str(asset.id),
        lab_definition_id='bac-orders-v1',
    )
    assert [item['identity_ref'] for item in payload['options']] == ['bob']


@pytest.fixture
def client(context):
    app = FastAPI()
    app.include_router(router, prefix='/api/v1/web-labs')
    app.dependency_overrides[get_current_user] = lambda: {'user_id': str(context[0].id)}
    with TestClient(app) as client:
        yield client
        client.portal.call(sync_to_async(connections.close_all, thread_sensitive=True))


def payload(context):
    return dict(project_id=str(context[1].id), asset_id=str(context[2].id),
                lab_definition_id='bac-orders-v1', credential_refs=[str(c.id) for c in context[-1]])


def test_api_credential_options_are_project_scoped(client, context):
    response = client.get('/api/v1/web-labs/credential-options', params={
        'project_id': str(context[1].id),
        'asset_id': str(context[2].id),
        'lab_definition_id': 'bac-orders-v1',
    })
    assert response.status_code == 200
    body = response.json()
    assert body['identity_refs'] == ['alice', 'bob']
    assert [row['identity_ref'] for row in body['options']] == ['alice', 'bob']
    assert 'encrypted_secret' not in response.text
    assert 'secret_fingerprint' not in response.text

    response = client.get('/api/v1/web-labs/credential-options', params={
        'project_id': str(context[1].id),
        'asset_id': str(uuid4()),
        'lab_definition_id': 'bac-orders-v1',
    })
    assert response.status_code == 404


def test_api_contract_unknown_lab_and_inaccessible_asset(client, context):
    assert client.post('/api/v1/web-labs/prepare', json=payload(context)).status_code == 200
    data = payload(context)
    data['lab_definition_id'] = 'unknown'
    response = client.post('/api/v1/web-labs/prepare', json=data)
    assert response.status_code == 422
    assert response.json()['detail']['code'] == 'unknown_lab_definition'
    data['asset_id'] = str(uuid4())
    assert client.post('/api/v1/web-labs/prepare', json=data).status_code == 404


@pytest.mark.parametrize('field', ['target', 'authorization_id', 'command', 'headers', 'provider_endpoint', 'secret'])
def test_api_rejects_execution_fields_and_does_not_echo_sensitive_input(client, context, field):
    data = payload(context)
    data[field] = 'sensitive-value-must-not-be-echoed'
    response = client.post('/api/v1/web-labs/prepare', json=data)
    assert response.status_code == 422
    assert 'sensitive-value-must-not-be-echoed' not in response.text
    assert response.json()['detail']['message_ar']


@pytest.mark.parametrize('field,value', [('project_id', 'invalid'), ('depth', 'unbounded'),
                                       ('credential_refs', ['inline-token']), ('lab_definition_id', '../fixture')])
def test_api_strict_input_types(client, context, field, value):
    data = payload(context)
    data[field] = value
    assert client.post('/api/v1/web-labs/prepare', json=data).status_code == 422


def test_duplicate_credential_refs_are_rejected(client, context):
    data = payload(context)
    data['credential_refs'] = [data['credential_refs'][0]] * 2
    assert client.post('/api/v1/web-labs/prepare', json=data).status_code == 422


def test_api_preview_does_not_mutate_in_its_database_thread(client, context, monkeypatch):
    original = CursorWrapper.execute
    captured = []

    def readonly(cursor, sql, params=None):
        assert not re.search(r'\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|TRUNCATE)\b', sql, re.I), sql
        captured.append(sql)
        return original(cursor, sql, params)

    monkeypatch.setattr(CursorWrapper, 'execute', readonly)
    response = client.post('/api/v1/web-labs/prepare', json=payload(context))
    assert response.status_code == 200
    assert captured
    assert response.json()['preview_only'] is True


def test_main_registration_and_fixture_revision_are_real_source_metadata():
    from fastapi_app.main import app
    assert '/api/v1/web-labs/prepare' in app.openapi()['paths']
    assert '/api/v1/web-labs/credential-options' in app.openapi()['paths']
    definition = preparation.lab_definition('bac-orders-v1')
    repository = Path(__file__).resolve().parents[4]
    fixture = repository / definition['fixture_path']
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == definition['fixture_revision_sha256']
