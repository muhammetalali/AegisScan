import pytest
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import override_settings
from rest_framework.test import APIClient

from django_project.projects.models import Project
from django_project.system import credential_vault
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import (
    CredentialVaultDenied,
    CredentialVaultUnavailable,
    authorize_credential_use,
    create_credential_secret,
    resolve_credential_secret,
    revoke_credential_secret,
    rotate_credential_secret,
)
from django_project.users.models import User, UserRole

CI_FERNET_KEY = 'Gda3DhfD-EcoacpdQeTFnHHH1Q_rxQZaUISBiMvSwUM='


@pytest.fixture(autouse=True)
def configured_vault(settings):
    settings.CREDENTIAL_VAULT_KEYS = CI_FERNET_KEY
    settings.CREDENTIAL_FINGERPRINT_KEY = 'ci-fingerprint-pepper-not-a-secret'


@pytest.fixture
def actor():
    return User.objects.create_user(
        email='vault-owner@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Vault',
        last_name='Owner',
        role=UserRole.ADMIN,
    )


@pytest.fixture
def project(actor):
    return Project.objects.create(
        name='Vault Project',
        slug='vault-project',
        owner=actor,
        environment=Project.Environment.PRODUCTION,
    )


@pytest.mark.django_db
def test_credential_create_api_never_returns_or_persists_plaintext(project, actor):
    client = APIClient()
    client.force_authenticate(actor)
    secret = 'super-sensitive-token-value-123'

    response = client.post(
        '/api/v1/credentials/',
        {
            'project': str(project.id),
            'name': 'production-api-token',
            'kind': CredentialSecret.Kind.TOKEN,
            'secret': secret,
            'scope': {'asset_types': ['api_endpoint'], 'env': 'production'},
        },
        format='json',
    )

    assert response.status_code == 201
    rendered = response.content.decode('utf-8')
    assert 'secret' not in response.json()
    assert secret not in rendered
    credential = CredentialSecret.objects.get(id=response.json()['id'])
    assert credential.project == project
    assert credential.status == CredentialSecret.Status.ACTIVE
    assert credential.version == 1
    assert secret not in credential.encrypted_secret
    assert len(credential.secret_fingerprint) == 64
    access = CredentialAccess.objects.get(credential=credential, operation=CredentialAccess.Operation.CREATE)
    assert access.result == CredentialAccess.Result.SUCCESS
    assert secret not in str(access.metadata)
    assert access.project == project


@pytest.mark.django_db
def test_internal_resolve_rotation_and_revoke_are_reference_based(project, actor):
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='scanner-login',
        kind=CredentialSecret.Kind.PASSWORD,
        secret='initial-secret-123',
        scope={'asset': 'authorized-only'},
    )

    assert resolve_credential_secret(credential=credential, actor=actor, purpose='scanner-fixture') == 'initial-secret-123'
    rotated = rotate_credential_secret(credential=credential, actor=actor, secret='rotated-secret-456')
    assert rotated.version == 2
    assert resolve_credential_secret(credential=rotated, actor=actor, purpose='scanner-fixture') == 'rotated-secret-456'
    revoke_credential_secret(credential=rotated, actor=actor, reason='test revocation')
    rotated.refresh_from_db()
    assert rotated.status == CredentialSecret.Status.REVOKED
    with pytest.raises(CredentialVaultDenied):
        resolve_credential_secret(credential=rotated, actor=actor, purpose='scanner-fixture')
    assert CredentialAccess.objects.filter(credential=rotated, result=CredentialAccess.Result.DENIED).exists()
    assert all('rotated-secret-456' not in str(event.metadata) for event in CredentialAccess.objects.filter(credential=rotated))


@pytest.mark.django_db
def test_credential_api_enforces_project_tenant_isolation(project, actor):
    other = User.objects.create_user(
        email='other-vault-admin@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Other',
        last_name='Admin',
        role=UserRole.ADMIN,
    )
    other_project = Project.objects.create(name='Other Project', slug='other-project', owner=other)
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='tenant-secret',
        kind=CredentialSecret.Kind.API_KEY,
        secret='tenant-secret-value',
    )

    client = APIClient()
    client.force_authenticate(other)
    list_response = client.get('/api/v1/credentials/', {'project': str(project.id)})
    retrieve_response = client.get(f'/api/v1/credentials/{credential.id}/')
    create_response = client.post(
        '/api/v1/credentials/',
        {
            'project': str(project.id),
            'name': 'cross-tenant-write',
            'kind': CredentialSecret.Kind.TOKEN,
            'secret': 'must-not-store',
        },
        format='json',
    )

    assert list_response.status_code == 200
    assert list_response.json()['count'] == 0
    assert retrieve_response.status_code == 404
    assert create_response.status_code == 404
    assert CredentialSecret.objects.filter(project=other_project).count() == 0
    assert CredentialSecret.objects.filter(name='cross-tenant-write').count() == 0


@pytest.mark.django_db
def test_authorize_use_api_returns_reference_not_secret(project, actor):
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='scanner-token',
        kind=CredentialSecret.Kind.TOKEN,
        secret='scanner-token-secret',
    )
    client = APIClient()
    client.force_authenticate(actor)

    response = client.post(
        f'/api/v1/credentials/{credential.id}/authorize-use/',
        {'purpose': 'native-capability-scan'},
        format='json',
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload['credential_ref'] == str(credential.id)
    assert payload['secret_available'] is True
    assert 'scanner-token-secret' not in response.content.decode('utf-8')
    credential.refresh_from_db()
    assert credential.last_used_by == actor
    assert credential.last_used_at is not None


@pytest.mark.django_db
def test_credential_access_ledger_is_append_only(project, actor):
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='append-only-secret',
        kind=CredentialSecret.Kind.GENERIC,
        secret='append-only-value',
    )
    access = CredentialAccess.objects.get(credential=credential, operation=CredentialAccess.Operation.CREATE)
    access.reason = 'tamper'
    with pytest.raises(ValidationError):
        access.save()
    with pytest.raises(ValidationError):
        CredentialAccess.objects.filter(id=access.id).delete()
    with pytest.raises(ValidationError):
        credential.delete()


@pytest.mark.django_db
def test_production_vault_fails_closed_without_key(project, actor):
    with override_settings(DEBUG=False, CREDENTIAL_VAULT_KEYS=''):
        with pytest.raises(CredentialVaultUnavailable):
            create_credential_secret(
                project=project,
                actor=actor,
                name='no-key-secret',
                kind=CredentialSecret.Kind.TOKEN,
                secret='not-written-without-key',
            )
    assert not CredentialSecret.objects.filter(name='no-key-secret').exists()


def _exercise_operation(operation, credential, actor):
    if operation == 'rotate':
        return rotate_credential_secret(credential=credential, actor=actor, secret='replacement-regression-secret')
    service = authorize_credential_use if operation == 'authorize' else resolve_credential_secret
    return service(credential=credential, actor=actor, purpose='credential-regression')


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('operation', ['authorize', 'resolve', 'rotate'])
@pytest.mark.parametrize('stale_instance', [False, True], ids=['fresh-reference', 'cached-reference'])
def test_revoked_denial_is_committed_without_mutating_secret(project, actor, operation, stale_instance):
    # Use real autocommit, not pytest-django's wrapping transaction, so closing
    # and reopening the PostgreSQL connection proves the denial was committed.
    assert not connection.in_atomic_block
    credential = create_credential_secret(
        project=project, actor=actor, name='denial-proof',
        kind=CredentialSecret.Kind.TOKEN, secret='denial-regression-secret',
    )
    original_ciphertext = credential.encrypted_secret
    original_fingerprint = credential.secret_fingerprint
    revoke_credential_secret(credential=CredentialSecret.objects.get(pk=credential.pk), actor=actor)
    if stale_instance:
        assert credential.status == CredentialSecret.Status.ACTIVE
    else:
        credential.refresh_from_db()

    with pytest.raises(CredentialVaultDenied):
        _exercise_operation(operation, credential, actor)

    assert not connection.in_atomic_block
    connection.close()
    credential.refresh_from_db()
    denied = CredentialAccess.objects.get(credential=credential, result=CredentialAccess.Result.DENIED)
    expected_operation = CredentialAccess.Operation.ROTATE if operation == 'rotate' else CredentialAccess.Operation.AUTHORIZE_USE
    assert denied.operation == expected_operation
    assert denied.project_id == project.pk
    assert denied.actor_id == actor.pk
    assert credential.status == CredentialSecret.Status.REVOKED
    assert credential.version == 1
    assert credential.encrypted_secret == original_ciphertext
    assert credential.secret_fingerprint == original_fingerprint
    assert credential.last_used_at is None
    assert credential.rotated_at is None
    assert credential.access_events.count() == 3  # create, revoke, denial


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('operation', ['authorize', 'resolve', 'rotate'])
def test_ledger_failure_rolls_back_successful_operation(project, actor, monkeypatch, operation):
    credential = create_credential_secret(
        project=project, actor=actor, name='ledger-failure-proof',
        kind=CredentialSecret.Kind.TOKEN, secret='ledger-failure-regression-secret',
    )
    original_ciphertext = credential.encrypted_secret
    original_fingerprint = credential.secret_fingerprint
    append_access = credential_vault._append_access
    fail_operation = {
        'authorize': CredentialAccess.Operation.AUTHORIZE_USE,
        'resolve': CredentialAccess.Operation.RESOLVE_INTERNAL,
        'rotate': CredentialAccess.Operation.ROTATE,
    }[operation]

    def fail_access_write(**kwargs):
        if kwargs['operation'] == fail_operation:
            raise RuntimeError('injected ledger write failure')
        return append_access(**kwargs)

    monkeypatch.setattr(credential_vault, '_append_access', fail_access_write)
    with pytest.raises(RuntimeError, match='injected ledger write failure'):
        _exercise_operation(operation, credential, actor)

    connection.close()
    credential.refresh_from_db()
    assert credential.version == 1
    assert credential.encrypted_secret == original_ciphertext
    assert credential.secret_fingerprint == original_fingerprint
    assert credential.last_used_at is None
    assert credential.last_used_by_id is None
    assert credential.rotated_at is None
    assert credential.rotated_by_id is None
    assert credential.access_events.count() == 1  # Only the original create.


@pytest.mark.django_db
def test_rotation_and_resolution_reload_current_database_version(project, actor):
    credential = create_credential_secret(
        project=project, actor=actor, name='current-version-proof',
        kind=CredentialSecret.Kind.TOKEN, secret='version-one-regression-secret',
    )
    cached = CredentialSecret.objects.get(pk=credential.pk)
    first = rotate_credential_secret(credential=credential, actor=actor, secret='version-two-regression-secret')
    second = rotate_credential_secret(credential=cached, actor=actor, secret='version-three-regression-secret')
    assert first.version == 2
    assert second.version == 3
    assert resolve_credential_secret(credential=cached, actor=actor, purpose='current-version') == 'version-three-regression-secret'
    resolved = CredentialAccess.objects.get(credential=credential, operation=CredentialAccess.Operation.RESOLVE_INTERNAL)
    assert resolved.metadata['version'] == 3


@pytest.mark.django_db
def test_decryption_failure_does_not_record_successful_use(project, actor):
    credential = create_credential_secret(
        project=project, actor=actor, name='decryption-failure-proof',
        kind=CredentialSecret.Kind.TOKEN, secret='decryption-regression-secret',
    )
    with override_settings(CREDENTIAL_VAULT_KEYS=credential_vault.Fernet.generate_key().decode('ascii')):
        with pytest.raises(CredentialVaultUnavailable):
            resolve_credential_secret(credential=credential, actor=actor, purpose='decryption-failure')
    credential.refresh_from_db()
    assert credential.last_used_at is None
    assert credential.last_used_by_id is None
    assert credential.access_events.count() == 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize('action,payload,operation', [
    ('authorize-use', {'purpose': 'revoked-api-proof'}, CredentialAccess.Operation.AUTHORIZE_USE),
    ('rotate', {'secret': 'denied-api-replacement-secret'}, CredentialAccess.Operation.ROTATE),
])
def test_revoked_api_returns_conflict_and_preserves_denial(project, actor, action, payload, operation):
    credential = create_credential_secret(
        project=project, actor=actor, name='revoked-api-proof',
        kind=CredentialSecret.Kind.TOKEN, secret='revoked-api-regression-secret',
    )
    client = APIClient()
    client.force_authenticate(actor)
    assert client.delete(f'/api/v1/credentials/{credential.pk}/').status_code == 204

    response = client.post(f'/api/v1/credentials/{credential.pk}/{action}/', payload, format='json')
    assert response.status_code == 409
    assert 'revoked-api-regression-secret' not in response.content.decode('utf-8')
    assert 'denied-api-replacement-secret' not in response.content.decode('utf-8')
    connection.close()
    credential.refresh_from_db()
    assert credential.status == CredentialSecret.Status.REVOKED
    assert credential.version == 1
    assert credential.last_used_at is None
    assert CredentialAccess.objects.filter(
        credential=credential, operation=operation, result=CredentialAccess.Result.DENIED,
    ).count() == 1
