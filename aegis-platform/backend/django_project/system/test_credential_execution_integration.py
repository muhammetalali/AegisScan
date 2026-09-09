from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from django_project.projects.models import Project
from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import CredentialVaultDenied, create_credential_secret
from django_project.users.models import User, UserRole
from fastapi_app.services.credential_execution import (
    assert_no_credential_material_leaked,
    authorize_credential_refs_for_execution,
    resolve_credential_refs_for_worker,
)
from fastapi_app.services.native_tool_runtime import run_native_tool

CI_FERNET_KEY = 'Gda3DhfD-EcoacpdQeTFnHHH1Q_rxQZaUISBiMvSwUM='


@pytest.fixture(autouse=True)
def configured_vault(settings):
    settings.CREDENTIAL_VAULT_KEYS = CI_FERNET_KEY
    settings.CREDENTIAL_FINGERPRINT_KEY = 'ci-fingerprint-pepper-not-a-secret'


@pytest.fixture
def actor():
    return User.objects.create_user(
        email='vault-execution-owner@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Vault',
        last_name='Execution',
        role=UserRole.ADMIN,
    )


@pytest.fixture
def project(actor):
    return Project.objects.create(
        name='Vault Execution Project',
        slug='vault-execution-project',
        owner=actor,
        environment=Project.Environment.PRODUCTION,
    )


class _CredentialAwareHandler(BaseHTTPRequestHandler):
    expected_token = ''
    seen_authorization: list[str] = []

    def do_HEAD(self):
        authorization = self.headers.get('Authorization', '')
        type(self).seen_authorization.append(authorization)
        if authorization == f'Bearer {type(self).expected_token}':
            self.send_response(200)
            self.send_header('X-Aegis-Auth', 'accepted')
        else:
            self.send_response(401)
            self.send_header('X-Aegis-Auth', 'missing')
        self.send_header('X-Aegis-Fixture', 'credential-bound')
        self.end_headers()

    def log_message(self, format, *args):  # noqa: A003 - stdlib signature
        return


def _start_credential_fixture(expected_token: str):
    _CredentialAwareHandler.expected_token = expected_token
    _CredentialAwareHandler.seen_authorization = []
    server = ThreadingHTTPServer(('127.0.0.1', 0), _CredentialAwareHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, _CredentialAwareHandler.seen_authorization


@pytest.mark.django_db
def test_native_runtime_resolves_credential_ref_without_leaking_secret(project, actor, monkeypatch):
    secret = 'vault-runtime-token-789'
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='runtime-bearer-token',
        kind=CredentialSecret.Kind.TOKEN,
        secret=secret,
        scope={'capabilities': ['web.security-headers']},
    )

    scheduled_context = authorize_credential_refs_for_execution(
        project_id=project.id,
        actor_id=actor.id,
        refs=[str(credential.id)],
        capability_id='web.security-headers',
        allowed_kinds=(CredentialSecret.Kind.TOKEN, CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.GENERIC),
    )
    materials, worker_context = resolve_credential_refs_for_worker(
        project_id=project.id,
        actor_id=actor.id,
        refs=[str(credential.id)],
        capability_id='web.security-headers',
        allowed_kinds=(CredentialSecret.Kind.TOKEN, CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.GENERIC),
    )

    assert scheduled_context['credential_refs'][0]['credential_ref'] == str(credential.id)
    assert worker_context['credential_refs'][0]['version'] == 1
    assert materials[0]['secret'] == secret
    assert secret not in str(scheduled_context)
    assert secret not in str(worker_context)

    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    server, thread, seen_authorization = _start_credential_fixture(secret)
    try:
        target = f'http://127.0.0.1:{server.server_port}/'
        result = run_native_tool('web.security-headers', target, {}, credential_materials=materials)
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()

    assert result.exit_code == 0, result.stderr
    assert seen_authorization == [f'Bearer {secret}']
    assert 'X-Aegis-Auth: accepted' in result.stdout
    assert 'X-Aegis-Fixture: credential-bound' in result.stdout
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert_no_credential_material_leaked(materials, result.stdout, result.stderr, scheduled_context, worker_context)
    assert CredentialAccess.objects.filter(
        credential=credential,
        operation=CredentialAccess.Operation.AUTHORIZE_USE,
        result=CredentialAccess.Result.SUCCESS,
    ).count() >= 2
    assert CredentialAccess.objects.filter(
        credential=credential,
        operation=CredentialAccess.Operation.RESOLVE_INTERNAL,
        result=CredentialAccess.Result.SUCCESS,
    ).exists()


@pytest.mark.django_db
def test_credential_binding_rejects_wrong_kind_and_records_denial(project, actor):
    credential = create_credential_secret(
        project=project,
        actor=actor,
        name='wrong-kind-password',
        kind=CredentialSecret.Kind.PASSWORD,
        secret='must-not-bind-to-bearer-mode',
    )

    with pytest.raises(CredentialVaultDenied):
        authorize_credential_refs_for_execution(
            project_id=project.id,
            actor_id=actor.id,
            refs=[str(credential.id)],
            capability_id='web.security-headers',
            allowed_kinds=(CredentialSecret.Kind.TOKEN,),
        )

    denied = CredentialAccess.objects.get(
        credential=credential,
        operation=CredentialAccess.Operation.AUTHORIZE_USE,
        result=CredentialAccess.Result.DENIED,
    )
    assert denied.metadata['credential_ref'] == str(credential.id)
    assert 'must-not-bind-to-bearer-mode' not in str(denied.metadata)
    assert 'must-not-bind-to-bearer-mode' not in denied.reason


def test_native_runtime_rejects_credential_material_for_non_credential_capability():
    with pytest.raises(ValueError, match='does not support credential-bound execution'):
        run_native_tool(
            'binary.xxd',
            '/bin/sh',
            {},
            credential_materials=({'credential_ref': 'fixture', 'kind': 'token', 'version': 1, 'secret': 'unused-secret'},),
        )
