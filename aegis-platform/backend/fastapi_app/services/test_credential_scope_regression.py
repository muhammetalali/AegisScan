from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialSecret
from django_project.system.credential_vault import create_credential_secret
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution


@pytest.mark.django_db
def test_non_kubernetes_credentials_remain_compatible_without_target_scope():
    user = get_user_model().objects.create_user(email='credential-regression@example.test', password='Credential-Regression-123!')
    project = Project.objects.create(name='Credential Regression', slug='credential-regression', owner=user)
    credential = create_credential_secret(
        project=project,
        actor=user,
        name='api-token',
        kind=CredentialSecret.Kind.TOKEN,
        secret='regression-token-value',
        scope={},
    )
    context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=user.id,
        refs=[str(credential.id)],
        capability_id='api.openapi-runtime-conformance',
        allowed_kinds=('token', 'api_key', 'generic'),
    )
    assert context['credential_refs'] == [
        {'credential_ref': str(credential.id), 'kind': 'token', 'version': 1}
    ]
