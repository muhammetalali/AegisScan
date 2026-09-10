from __future__ import annotations

import json

import pytest
from django.contrib.auth import get_user_model

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from fastapi_app.services.credential_execution import (
    authorize_credential_refs_for_execution,
    resolve_credential_refs_for_worker,
)


def _project_and_user():
    user = get_user_model().objects.create_user(email='cloud-scope@example.test', password='Cloud-Scope-123!')
    project = Project.objects.create(name='Cloud Scope', slug='cloud-scope', owner=user)
    return project, user


@pytest.mark.django_db
def test_aws_cloud_credential_scope_must_exactly_match_authorized_account():
    project, user = _project_and_user()
    secret = json.dumps({'provider': 'aws', 'access_key_id': 'AKIAEXAMPLE', 'secret_access_key': 'scope-secret'})
    credential = create_credential_secret(
        project=project, actor=user, name='aws-reader', kind=CredentialSecret.Kind.CLOUD_ACCESS_KEY,
        secret=secret, scope={'provider': 'aws', 'account_id': '123456789012'},
    )
    context = authorize_credential_refs_for_execution(
        project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
        capability_id='cloud.read-only-posture', allowed_kinds=('cloud_access_key',),
        purpose='test:cloud:schedule', target='aws://123456789012',
    )
    assert context['credential_refs'][0]['credential_ref'] == str(credential.id)
    assert 'scope-secret' not in json.dumps(context)

    with pytest.raises(CredentialVaultDenied, match='not scoped'):
        authorize_credential_refs_for_execution(
            project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
            capability_id='cloud.read-only-posture', allowed_kinds=('cloud_access_key',),
            purpose='test:cloud:deny', target='aws://999999999999',
        )
    denial = CredentialAccess.objects.filter(
        credential=credential, purpose='test:cloud:deny', result=CredentialAccess.Result.DENIED
    ).latest('created_at')
    assert denial.metadata['scope_matches_target'] is False
    assert 'scope-secret' not in json.dumps(denial.metadata)
    assert 'scope-secret' not in denial.reason


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('scope', 'target'),
    [
        (
            {'provider': 'azure', 'subscription_id': '11111111-2222-3333-4444-555555555555'},
            'azure://11111111-2222-3333-4444-555555555555',
        ),
        ({'provider': 'gcp', 'project_id': 'aegis-prod-123'}, 'gcp://aegis-prod-123'),
    ],
)
def test_azure_and_gcp_cloud_scope_authorization(scope: dict[str, str], target: str):
    project, user = _project_and_user()
    credential = create_credential_secret(
        project=project, actor=user, name='cloud-reader', kind=CredentialSecret.Kind.CLOUD_ACCESS_KEY,
        secret=json.dumps({'provider': scope['provider'], 'opaque': 'worker-only'}), scope=scope,
    )
    context = authorize_credential_refs_for_execution(
        project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
        capability_id='cloud.read-only-posture', allowed_kinds=('cloud_access_key',),
        target=target,
    )
    assert context['credential_refs'][0]['kind'] == 'cloud_access_key'


@pytest.mark.django_db
def test_worker_resolves_cloud_secret_only_after_scope_revalidation():
    project, user = _project_and_user()
    secret = json.dumps({'provider': 'aws', 'access_key_id': 'AKIAWORKER', 'secret_access_key': 'worker-secret-value'})
    credential = create_credential_secret(
        project=project, actor=user, name='aws-worker', kind=CredentialSecret.Kind.CLOUD_ACCESS_KEY,
        secret=secret, scope={'provider': 'aws', 'account_id': '123456789012'},
    )
    materials, context = resolve_credential_refs_for_worker(
        project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
        capability_id='cloud.read-only-posture', allowed_kinds=('cloud_access_key',),
        target='aws://123456789012',
    )
    assert materials[0]['secret'] == secret
    assert context['credential_material_handling'] == 'worker-resolved-redacted'
    assert 'worker-secret-value' not in json.dumps(context)
    assert CredentialAccess.objects.filter(
        credential=credential, operation=CredentialAccess.Operation.RESOLVE, result=CredentialAccess.Result.ALLOWED
    ).exists()
