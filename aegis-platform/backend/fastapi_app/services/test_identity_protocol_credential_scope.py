from __future__ import annotations

import uuid

import pytest
from django.contrib.auth import get_user_model

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution


CAPABILITY = 'identity-protocol.security-validation'
ORIGIN = 'https://identity-fixture.example'
IDENTITY = 'alice'


def _fixture():
    suffix = uuid.uuid4().hex[:10]
    user = get_user_model().objects.create_user(
        email=f'identity-vault-{suffix}@example.test',
        password='Identity-Vault-Test-Only-123!',
    )
    project = Project.objects.create(
        name=f'Identity Vault {suffix}',
        slug=f'identity-vault-{suffix}',
        owner=user,
    )
    return user, project


def _credential(project, user, *, origin: str = ORIGIN, identity: str = IDENTITY):
    return create_credential_secret(
        project=project,
        actor=user,
        name='identity-protocol-token',
        kind=CredentialSecret.Kind.TOKEN,
        secret='identity-protocol-secret-material',
        scope={
            'protocol_origin': origin,
            'protocol_identity_ref': identity,
        },
    )


@pytest.mark.django_db
def test_identity_protocol_capability_enforces_origin_and_identity_binding():
    user, project = _fixture()
    credential = _credential(project, user)

    context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=user.id,
        refs=[str(credential.id)],
        capability_id=CAPABILITY,
        allowed_kinds=('token', 'api_key', 'generic'),
        purpose='identity-protocol:test:authorize',
        target=ORIGIN,
        identity_ref=IDENTITY,
    )

    assert context['credential_material_handling'] == 'reference-authorized-only'
    assert context['credential_refs'] == [{
        'credential_ref': str(credential.id),
        'kind': 'token',
        'version': 1,
        'protocol_identity_ref': IDENTITY,
    }]
    assert 'identity-protocol-secret-material' not in str(context)


@pytest.mark.django_db
@pytest.mark.parametrize(
    ('target', 'identity_ref'),
    [
        ('https://other.example', IDENTITY),
        (ORIGIN, 'mallory'),
    ],
)
def test_identity_protocol_capability_denies_scope_or_identity_mismatch(target, identity_ref):
    user, project = _fixture()
    credential = _credential(project, user)

    with pytest.raises(CredentialVaultDenied, match='not scoped'):
        authorize_credential_refs_for_execution(
            project_id=project.id,
            actor_id=user.id,
            refs=[str(credential.id)],
            capability_id=CAPABILITY,
            allowed_kinds=('token', 'api_key', 'generic'),
            purpose='identity-protocol:test:deny',
            target=target,
            identity_ref=identity_ref,
        )

    denied = CredentialAccess.objects.filter(
        credential=credential,
        result=CredentialAccess.Result.DENIED,
    ).latest('created_at')
    assert denied.metadata['scope_type'] == 'protocol_origin+identity'
    assert denied.metadata['scope_matches_target'] is (target == ORIGIN)
    assert denied.metadata['identity_binding_matches'] is (identity_ref == IDENTITY)
