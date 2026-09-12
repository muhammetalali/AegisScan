from __future__ import annotations

from typing import Any

from django.db import transaction

from enterprise.web_security_models import WebSecurityObservation, WebSecurityValidationRun
from fastapi_app.services.web_security_foundation import (
    CONTRACT_VERSION,
    canonical_digest,
    privacy_fingerprint,
    upsert_graph_snapshot,
)


def _identity(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get('identity')
    return value if isinstance(value, dict) else {}


def _resource(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get('resource')
    return value if isinstance(value, dict) else {}


def _decision(allowed: bool) -> str:
    return (
        WebSecurityObservation.Decision.ALLOWED
        if allowed
        else WebSecurityObservation.Decision.DENIED
    )


def _common_failures(case: dict[str, Any], accepted: bool, expected: bool) -> list[str]:
    failures: list[str] = []
    if accepted != expected:
        failures.append('observed identity protocol decision does not match expected policy')

    identity = _identity(case)
    resource = _resource(case)
    identity_tenant = str(identity.get('tenant_ref') or '')
    resource_tenant = str(resource.get('tenant_ref') or '')
    if accepted and identity_tenant and resource_tenant and identity_tenant != resource_tenant:
        failures.append('cross-tenant identity protocol use was accepted')
    return failures


def _validate_token(case: dict[str, Any], accepted: bool, failures: list[str]) -> None:
    algorithm = str(case.get('token_algorithm') or '')
    allowed = {str(value) for value in (case.get('allowed_algorithms') or [])}
    if accepted and algorithm and allowed and algorithm not in allowed:
        failures.append('token algorithm was accepted outside configured allowlist')
    if accepted and not bool(case.get('signature_valid', True)):
        failures.append('invalid token signature was accepted')

    issuer = str(case.get('issuer') or '')
    expected_issuer = str(case.get('expected_issuer') or '')
    if accepted and expected_issuer and issuer != expected_issuer:
        failures.append('token issuer mismatch was accepted')

    audiences = {str(value) for value in (case.get('audiences') or [])}
    expected_audiences = {str(value) for value in (case.get('expected_audiences') or [])}
    if accepted and expected_audiences and audiences.isdisjoint(expected_audiences):
        failures.append('token audience mismatch was accepted')

    if accepted and bool(case.get('token_expired')):
        failures.append('expired token was accepted')
    if accepted and bool(case.get('token_not_yet_valid')):
        failures.append('not-yet-valid token was accepted')
    if accepted and str(case.get('kid') or '') and not bool(case.get('kid_resolved', True)):
        failures.append('token with unresolved signing key was accepted')
    if accepted and str(case.get('signing_key_status') or '') in {'retired', 'revoked'}:
        failures.append('token signed by inactive key was accepted')
    if accepted and bool(case.get('token_binding_required')) and not bool(case.get('token_binding_present')):
        failures.append('token binding requirement was bypassed')
    if bool(case.get('replay_detected')) and accepted and not bool(case.get('replay_rejected', True)):
        failures.append('token replay was accepted')


def _validate_oauth_oidc(case: dict[str, Any], accepted: bool, failures: list[str]) -> None:
    redirect_uri = str(case.get('redirect_uri') or '')
    registered = {str(value) for value in (case.get('registered_redirect_uris') or [])}
    if accepted and redirect_uri and registered and redirect_uri not in registered:
        failures.append('unregistered redirect URI was accepted')
    if accepted and bool(case.get('state_required', True)) and not bool(case.get('state_verified', True)):
        failures.append('OAuth/OIDC state validation was bypassed')
    if accepted and bool(case.get('nonce_required')) and not bool(case.get('nonce_verified', True)):
        failures.append('OIDC nonce validation was bypassed')
    if accepted and bool(case.get('pkce_required', True)) and not bool(case.get('pkce_verified', True)):
        failures.append('PKCE validation was bypassed')
    if accepted and bool(case.get('pkce_required', True)) and str(case.get('pkce_method') or '') != 'S256':
        failures.append('weak or absent PKCE method was accepted')
    if bool(case.get('authorization_code_reused')) and accepted and not bool(case.get('authorization_code_reuse_rejected', True)):
        failures.append('authorization code replay was accepted')


def _validate_saml(case: dict[str, Any], accepted: bool, failures: list[str]) -> None:
    if not accepted:
        return
    signature_required = bool(case.get('saml_signature_required', True))
    if signature_required and not bool(case.get('saml_response_signature_valid', True)):
        failures.append('SAML response with invalid signature was accepted')
    if signature_required and not bool(case.get('saml_assertion_signature_valid', True)):
        failures.append('SAML assertion with invalid signature was accepted')
    expected_audience = str(case.get('saml_expected_audience') or '')
    observed_audience = str(case.get('saml_observed_audience') or '')
    if expected_audience and observed_audience != expected_audience:
        failures.append('SAML audience mismatch was accepted')
    expected_recipient = str(case.get('saml_expected_recipient') or '')
    observed_recipient = str(case.get('saml_observed_recipient') or '')
    if expected_recipient and observed_recipient != expected_recipient:
        failures.append('SAML recipient mismatch was accepted')
    if not bool(case.get('saml_destination_valid', True)):
        failures.append('invalid SAML destination was accepted')
    if not bool(case.get('saml_in_response_to_valid', True)):
        failures.append('invalid SAML InResponseTo binding was accepted')
    if not bool(case.get('saml_conditions_valid', True)):
        failures.append('invalid SAML conditions were accepted')
    if not bool(case.get('saml_subject_confirmation_valid', True)):
        failures.append('invalid SAML subject confirmation was accepted')
    if not bool(case.get('saml_signature_wrapping_rejected', True)):
        failures.append('SAML signature wrapping condition was accepted')


def _validate_session(case: dict[str, Any], accepted: bool, failures: list[str]) -> None:
    state = str(case.get('session_state') or 'unknown')
    if accepted and state in {'expired', 'revoked'}:
        failures.append(f'{state} application session remained usable')
    if accepted and bool(case.get('session_fixation_detected')):
        failures.append('session fixation condition was accepted')
    if accepted and not bool(case.get('session_rotated_after_auth', True)):
        failures.append('session identifier was not rotated after authentication')
    if accepted and not bool(case.get('session_rotated_after_privilege_change', True)):
        failures.append('session identifier was not rotated after privilege change')
    if accepted and not bool(case.get('cookie_secure', True)):
        failures.append('session cookie missing Secure attribute')
    if accepted and not bool(case.get('cookie_http_only', True)):
        failures.append('session cookie missing HttpOnly attribute')
    if accepted and str(case.get('cookie_same_site') or '') == 'None' and not bool(case.get('cookie_secure', True)):
        failures.append('SameSite=None session cookie was accepted without Secure')
    if accepted and bool(case.get('csrf_binding_required')) and not bool(case.get('csrf_binding_verified', True)):
        failures.append('session CSRF binding requirement was bypassed')


def evaluate_identity_protocol_case(case: dict[str, Any]) -> dict[str, Any]:
    protocol = str(case.get('protocol') or '').lower()
    expected = bool(case.get('expected_allowed'))
    accepted = bool(case.get('server_accepted'))
    failures = _common_failures(case, accepted, expected)

    if protocol in {'jwt', 'oidc'}:
        _validate_token(case, accepted, failures)
    if protocol in {'oauth2', 'oidc'}:
        _validate_oauth_oidc(case, accepted, failures)
    if protocol == 'saml':
        _validate_saml(case, accepted, failures)
    if protocol == 'session':
        _validate_session(case, accepted, failures)

    semantic = {
        'protocol': protocol,
        'session_ref_hmac': (
            privacy_fingerprint(str(case.get('session_ref') or ''))
            if str(case.get('session_ref') or '')
            else ''
        ),
        'token_algorithm': str(case.get('token_algorithm') or ''),
        'allowed_algorithms': sorted(str(v) for v in (case.get('allowed_algorithms') or [])),
        'signature_valid': bool(case.get('signature_valid', True)),
        'issuer_matches': (
            not str(case.get('expected_issuer') or '')
            or str(case.get('issuer') or '') == str(case.get('expected_issuer') or '')
        ),
        'audience_match': (
            not case.get('expected_audiences')
            or not set(str(v) for v in (case.get('audiences') or [])).isdisjoint(
                set(str(v) for v in (case.get('expected_audiences') or []))
            )
        ),
        'token_expired': bool(case.get('token_expired')),
        'token_not_yet_valid': bool(case.get('token_not_yet_valid')),
        'kid_present': bool(str(case.get('kid') or '')),
        'kid_resolved': bool(case.get('kid_resolved', True)),
        'signing_key_status': str(case.get('signing_key_status') or 'unknown'),
        'token_binding_required': bool(case.get('token_binding_required')),
        'token_binding_present': bool(case.get('token_binding_present')),
        'replay_detected': bool(case.get('replay_detected')),
        'redirect_uri_registered': (
            not str(case.get('redirect_uri') or '')
            or not case.get('registered_redirect_uris')
            or str(case.get('redirect_uri') or '') in {str(v) for v in case.get('registered_redirect_uris') or []}
        ),
        'state_verified': bool(case.get('state_verified', True)),
        'nonce_verified': bool(case.get('nonce_verified', True)),
        'pkce_verified': bool(case.get('pkce_verified', True)),
        'pkce_method': str(case.get('pkce_method') or ''),
        'authorization_code_reused': bool(case.get('authorization_code_reused')),
        'saml_response_signature_valid': bool(case.get('saml_response_signature_valid', True)),
        'saml_assertion_signature_valid': bool(case.get('saml_assertion_signature_valid', True)),
        'saml_destination_valid': bool(case.get('saml_destination_valid', True)),
        'saml_in_response_to_valid': bool(case.get('saml_in_response_to_valid', True)),
        'saml_conditions_valid': bool(case.get('saml_conditions_valid', True)),
        'saml_subject_confirmation_valid': bool(case.get('saml_subject_confirmation_valid', True)),
        'saml_signature_wrapping_rejected': bool(case.get('saml_signature_wrapping_rejected', True)),
        'session_state': str(case.get('session_state') or 'unknown'),
        'session_rotated_after_auth': bool(case.get('session_rotated_after_auth', True)),
        'session_rotated_after_privilege_change': bool(case.get('session_rotated_after_privilege_change', True)),
        'session_fixation_detected': bool(case.get('session_fixation_detected')),
        'cookie_secure': bool(case.get('cookie_secure', True)),
        'cookie_http_only': bool(case.get('cookie_http_only', True)),
        'cookie_same_site': str(case.get('cookie_same_site') or 'Unknown'),
        'csrf_binding_verified': bool(case.get('csrf_binding_verified', True)),
        'failures': failures,
    }
    return {
        'passed': not failures,
        'expected_allowed': expected,
        'observed_decision': _decision(accepted),
        'semantic': semantic,
        'evidence_fingerprint': canonical_digest(semantic),
        'reason': '; '.join(failures) if failures else 'identity protocol invariants satisfied',
    }


def _project_graph(project, case: dict[str, Any], result: dict[str, Any]) -> None:
    identity = _identity(case)
    resource = _resource(case)
    protocol = str(case.get('protocol') or '')
    identity_ref = str(identity.get('ref') or '')
    resource_ref = str(resource.get('ref') or '')
    session_hash = result['semantic'].get('session_ref_hmac') or ''
    protocol_ref = f'identity-protocol:{canonical_digest([protocol, case.get("endpoint"), identity_ref])[:32]}'
    nodes = [
        {
            'plane': 'identity',
            'kind': 'identity',
            'external_ref': f'identity:{identity_ref}',
            'label': identity_ref,
            'protocol': protocol,
            'tenant_ref': str(identity.get('tenant_ref') or ''),
            'properties': {'identity_type': identity.get('type'), 'role': identity.get('role')},
            'provenance': {'source': 'identity_protocol_security'},
        },
        {
            'plane': 'application',
            'kind': 'resource',
            'external_ref': f'resource:{resource_ref}',
            'label': resource_ref,
            'protocol': protocol,
            'tenant_ref': str(resource.get('tenant_ref') or ''),
            'properties': {'resource_type': resource.get('type')},
            'provenance': {'source': 'identity_protocol_security'},
        },
        {
            'plane': 'identity',
            'kind': 'channel',
            'external_ref': protocol_ref,
            'label': f'{protocol}:{case.get("operation") or "authenticate"}',
            'protocol': protocol,
            'tenant_ref': str(identity.get('tenant_ref') or ''),
            'properties': {
                'endpoint': str(case.get('endpoint') or ''),
                'last_validation_passed': result['passed'],
                'evidence_fingerprint': result['evidence_fingerprint'],
            },
            'provenance': {'source': 'identity_protocol_security'},
        },
    ]
    edges = [
        {
            'source_ref': f'identity:{identity_ref}',
            'target_ref': protocol_ref,
            'relation': 'authenticates_via',
            'properties': {'case_ref': case.get('ref')},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'identity_protocol_security'},
        },
        {
            'source_ref': protocol_ref,
            'target_ref': f'resource:{resource_ref}',
            'relation': 'authorizes_resource',
            'properties': {},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'identity_protocol_security'},
        },
    ]
    if session_hash:
        session_ref = f'session:{session_hash}'
        nodes.append({
            'plane': 'identity',
            'kind': 'session',
            'external_ref': session_ref,
            'label': f'session:{session_hash[:16]}',
            'protocol': protocol,
            'tenant_ref': str(identity.get('tenant_ref') or ''),
            'properties': {'session_ref_hmac': session_hash},
            'provenance': {'source': 'identity_protocol_security'},
        })
        edges.append({
            'source_ref': protocol_ref,
            'target_ref': session_ref,
            'relation': 'establishes_session',
            'properties': {},
            'evidence_refs': [result['evidence_fingerprint']],
            'provenance': {'source': 'identity_protocol_security'},
        })
    upsert_graph_snapshot(project, nodes, edges)


@transaction.atomic
def run_identity_protocol_security(
    project,
    actor_id: str,
    cases: list[dict[str, Any]],
    governance: dict[str, Any] | None = None,
):
    evaluated = [(case, evaluate_identity_protocol_case(case)) for case in cases]
    for case, result in evaluated:
        _project_graph(project, case, result)

    summary: dict[str, Any] = {
        'total': len(evaluated),
        'passed': sum(1 for _case, result in evaluated if result['passed']),
        'failed': sum(1 for _case, result in evaluated if not result['passed']),
        'protocols': sorted({str(case.get('protocol') or '') for case, _result in evaluated}),
    }
    if governance is not None:
        summary['execution_budget'] = {
            'profile_id': str(governance.get('profile_id') or ''),
            'profile_sha256': str(governance.get('profile_sha256') or ''),
            'environment': str(governance.get('environment') or ''),
            'allowed': bool(governance.get('allowed')),
        }
        if isinstance(governance.get('credential_bindings'), list):
            summary['credential_bindings'] = governance['credential_bindings']

    run = WebSecurityValidationRun.objects.create(
        project=project,
        kind=WebSecurityValidationRun.Kind.IDENTITY_PROTOCOL_SECURITY,
        status=WebSecurityValidationRun.Status.COMPLETED,
        contract_version=CONTRACT_VERSION,
        input_sha256=canonical_digest(cases),
        summary=summary,
        created_by_id=actor_id,
    )

    observations: list[WebSecurityObservation] = []
    for case, result in evaluated:
        identity = _identity(case)
        resource = _resource(case)
        observations.append(WebSecurityObservation(
            run=run,
            case_ref=str(case.get('ref') or ''),
            identity_ref=str(identity.get('ref') or ''),
            identity_type=str(identity.get('type') or ''),
            role=str(identity.get('role') or ''),
            tenant_ref=str(identity.get('tenant_ref') or ''),
            resource_ref=str(resource.get('ref') or ''),
            resource_tenant_ref=str(resource.get('tenant_ref') or ''),
            endpoint=str(case.get('endpoint') or ''),
            method='IDENTITY',
            operation=str(case.get('operation') or ''),
            expected_allowed=result['expected_allowed'],
            observed_decision=result['observed_decision'],
            passed=result['passed'],
            semantic=result['semantic'],
            evidence_fingerprint=result['evidence_fingerprint'],
            reason=result['reason'],
        ))
    WebSecurityObservation.objects.bulk_create(observations)
    return run, observations
