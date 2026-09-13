
from __future__ import annotations

import uuid

import pytest
from django.contrib.auth import get_user_model

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution

CAPABILITY = 'cache-origin.security-validation'
ORIGIN = 'https://cache-fixture.example'
IDENTITY = 'alice'


def _fixture():
    suffix = uuid.uuid4().hex[:10]
    user = get_user_model().objects.create_user(email=f'cache-vault-{suffix}@example.test', password='Cache-Vault-Test-Only-123!')
    project = Project.objects.create(name=f'Cache Vault {suffix}', slug=f'cache-vault-{suffix}', owner=user)
    credential = create_credential_secret(
        project=project, actor=user, name='cache-origin-token', kind=CredentialSecret.Kind.TOKEN,
        secret='cache-origin-secret-material',
        scope={'protocol_origin': ORIGIN, 'protocol_identity_ref': IDENTITY},
    )
    return user, project, credential


@pytest.mark.django_db
def test_cache_origin_capability_enforces_origin_and_identity_binding():
    user, project, credential = _fixture()
    context = authorize_credential_refs_for_execution(
        project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
        capability_id=CAPABILITY, allowed_kinds=('token', 'api_key', 'generic'),
        purpose='cache-origin:test', target=ORIGIN, identity_ref=IDENTITY,
    )
    assert context['credential_material_handling'] == 'reference-authorized-only'
    assert context['credential_refs'][0]['protocol_identity_ref'] == IDENTITY
    assert 'cache-origin-secret-material' not in str(context)


@pytest.mark.django_db
@pytest.mark.parametrize(('target', 'identity_ref'), [('https://other.example', IDENTITY), (ORIGIN, 'mallory')])
def test_cache_origin_capability_denies_scope_or_identity_mismatch(target, identity_ref):
    user, project, credential = _fixture()
    with pytest.raises(CredentialVaultDenied, match='not scoped'):
        authorize_credential_refs_for_execution(
            project_id=project.id, actor_id=user.id, refs=[str(credential.id)],
            capability_id=CAPABILITY, allowed_kinds=('token', 'api_key', 'generic'),
            purpose='cache-origin:test-deny', target=target, identity_ref=identity_ref,
        )
    denied = CredentialAccess.objects.filter(
        credential=credential, result=CredentialAccess.Result.DENIED,
    ).latest('created_at')
    assert denied.metadata['scope_type'] == 'protocol_origin+identity'
    assert denied.metadata['scope_matches_target'] is (target == ORIGIN)
    assert denied.metadata['identity_binding_matches'] is (identity_ref == IDENTITY)
