from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.web_security_models import SecurityGraphNode, WebSecurityValidationRun
from fastapi_app.contracts.identity_protocol_security import IdentityProtocolCaseIn
from fastapi_app.services.identity_protocol_security import (
    evaluate_identity_protocol_case,
    run_identity_protocol_security,
)


def _identity(tenant: str = 'tenant-a') -> dict:
    return {
        'ref': 'alice',
        'type': 'user',
        'role': 'admin',
        'tenant_ref': tenant,
        'scopes': ['records:read'],
    }


def _resource(tenant: str = 'tenant-a') -> dict:
    return {
        'ref': 'record-a',
        'type': 'record',
        'tenant_ref': tenant,
        'owner_ref': 'alice',
    }


def _base(protocol: str) -> dict:
    return {
        'ref': f'{protocol}-case',
        'protocol': protocol,
        'identity': _identity(),
        'resource': _resource(),
        'endpoint': f'https://fixture.example/{protocol}',
        'operation': 'authenticate',
        'session_ref': 'opaque-session-fixture',
        'expected_allowed': False,
        'server_accepted': True,
    }


def test_contract_forbids_raw_token_or_assertion_material():
    case = _base('jwt')
    case['raw_token'] = 'must-never-be-accepted'
    with pytest.raises(ValidationError):
        IdentityProtocolCaseIn.model_validate(case)

    case = _base('saml')
    case['raw_assertion'] = '<Assertion>secret</Assertion>'
    with pytest.raises(ValidationError):
        IdentityProtocolCaseIn.model_validate(case)


def test_jwt_security_detects_crypto_claim_key_binding_and_replay_failures():
    case = _base('jwt')
    case.update({
        'token_algorithm': 'none',
        'allowed_algorithms': ['RS256'],
        'signature_valid': False,
        'issuer': 'https://evil.example',
        'expected_issuer': 'https://issuer.example',
        'audiences': ['wrong-api'],
        'expected_audiences': ['records-api'],
        'token_expired': True,
        'kid': 'retired-key',
        'kid_resolved': False,
        'signing_key_status': 'revoked',
        'token_binding_required': True,
        'token_binding_present': False,
        'replay_detected': True,
        'replay_rejected': False,
    })
    result = evaluate_identity_protocol_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in (
        'algorithm', 'signature', 'issuer', 'audience', 'expired', 'signing key',
        'inactive key', 'token binding', 'replay', 'expected policy',
    ):
        assert marker in joined
    assert len(result['evidence_fingerprint']) == 64
    assert 'opaque-session-fixture' not in str(result['semantic'])


def test_oidc_security_detects_redirect_state_nonce_pkce_and_code_replay():
    case = _base('oidc')
    case.update({
        'signature_valid': True,
        'issuer': 'https://issuer.example',
        'expected_issuer': 'https://issuer.example',
        'audiences': ['client-a'],
        'expected_audiences': ['client-a'],
        'redirect_uri': 'https://evil.example/callback',
        'registered_redirect_uris': ['https://app.example/callback'],
        'state_required': True,
        'state_verified': False,
        'nonce_required': True,
        'nonce_verified': False,
        'pkce_required': True,
        'pkce_verified': False,
        'pkce_method': 'plain',
        'authorization_code_reused': True,
        'authorization_code_reuse_rejected': False,
    })
    result = evaluate_identity_protocol_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in ('redirect URI', 'state', 'nonce', 'PKCE', 'authorization code replay'):
        assert marker in joined


def test_saml_security_detects_signature_audience_recipient_and_binding_failures():
    case = _base('saml')
    case.update({
        'saml_signature_required': True,
        'saml_response_signature_valid': False,
        'saml_assertion_signature_valid': False,
        'saml_expected_audience': 'urn:aegis:sp',
        'saml_observed_audience': 'urn:other:sp',
        'saml_expected_recipient': 'https://app.example/saml/acs',
        'saml_observed_recipient': 'https://evil.example/acs',
        'saml_destination_valid': False,
        'saml_in_response_to_valid': False,
        'saml_conditions_valid': False,
        'saml_subject_confirmation_valid': False,
        'saml_signature_wrapping_rejected': False,
    })
    result = evaluate_identity_protocol_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in (
        'response with invalid signature', 'assertion with invalid signature',
        'audience mismatch', 'recipient mismatch', 'destination', 'InResponseTo',
        'conditions', 'subject confirmation', 'signature wrapping',
    ):
        assert marker in joined


def test_session_security_detects_revocation_fixation_rotation_cookie_and_csrf_failures():
    case = _base('session')
    case.update({
        'session_state': 'revoked',
        'session_fixation_detected': True,
        'session_rotated_after_auth': False,
        'session_rotated_after_privilege_change': False,
        'cookie_secure': False,
        'cookie_http_only': False,
        'cookie_same_site': 'None',
        'csrf_binding_required': True,
        'csrf_binding_verified': False,
    })
    result = evaluate_identity_protocol_case(case)
    assert result['passed'] is False
    joined = ' | '.join(result['semantic']['failures'])
    for marker in (
        'revoked application session', 'fixation', 'rotated after authentication',
        'rotated after privilege change', 'Secure', 'HttpOnly', 'SameSite=None', 'CSRF',
    ):
        assert marker in joined


def test_cross_tenant_identity_protocol_use_is_detected():
    case = _base('jwt')
    case['resource'] = _resource('tenant-b')
    result = evaluate_identity_protocol_case(case)
    assert result['passed'] is False
    assert 'cross-tenant' in ' | '.join(result['semantic']['failures'])


def _user_project(prefix: str):
    suffix = uuid.uuid4().hex[:10]
    user = User.objects.create_user(
        email=f'{prefix}-{suffix}@example.com',
        password='Identity-Protocol-Test-Only-Password!42',
        first_name='Identity',
        last_name='Protocol',
    )
    project = Project.objects.create(
        name=f'{prefix}-{suffix}',
        slug=f'{prefix}-{suffix}',
        owner=user,
        environment=Project.Environment.STAGING,
    )
    return user, project


@pytest.mark.django_db
def test_identity_protocol_run_persists_immutable_observation_and_graph_projection():
    user, project = _user_project('identity-protocol')
    case = _base('oidc')
    case.update({
        'expected_allowed': True,
        'server_accepted': True,
        'signature_valid': True,
        'issuer': 'https://issuer.example',
        'expected_issuer': 'https://issuer.example',
        'audiences': ['client-a'],
        'expected_audiences': ['client-a'],
        'redirect_uri': 'https://app.example/callback',
        'registered_redirect_uris': ['https://app.example/callback'],
        'state_verified': True,
        'nonce_required': True,
        'nonce_verified': True,
        'pkce_required': True,
        'pkce_verified': True,
        'pkce_method': 'S256',
    })
    run, observations = run_identity_protocol_security(project, str(user.id), [case])
    assert run.kind == WebSecurityValidationRun.Kind.IDENTITY_PROTOCOL_SECURITY
    assert run.summary['passed'] == 1
    assert run.summary['failed'] == 0
    assert run.summary['protocols'] == ['oidc']
    assert len(observations) == 1
    assert observations[0].passed is True
    assert observations[0].semantic['session_ref_hmac']
    assert 'opaque-session-fixture' not in str(observations[0].semantic)
    assert SecurityGraphNode.objects.filter(project=project, plane='identity', protocol='oidc').exists()

    with pytest.raises(RuntimeError, match='immutable'):
        WebSecurityValidationRun.objects.filter(pk=run.pk).update(status='failed')
