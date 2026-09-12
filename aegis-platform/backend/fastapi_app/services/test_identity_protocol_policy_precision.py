from fastapi_app.contracts.identity_protocol_security import IdentityProtocolCaseIn
from fastapi_app.services.identity_protocol_security import evaluate_identity_protocol_case


def _base(protocol: str) -> dict:
    return {
        'ref': f'{protocol}-precision',
        'protocol': protocol,
        'identity': {
            'ref': 'alice',
            'type': 'user',
            'role': 'viewer',
            'tenant_ref': 'tenant-a',
            'scopes': [],
        },
        'resource': {
            'ref': 'record-a',
            'type': 'record',
            'tenant_ref': 'tenant-a',
            'owner_ref': 'alice',
        },
        'endpoint': 'https://identity-fixture.example/login',
        'expected_allowed': True,
        'server_accepted': True,
    }


def test_jwt_alg_none_is_rejected_even_without_an_explicit_allowlist():
    case = _base('jwt')
    case.update({'token_algorithm': 'none', 'signature_valid': True})
    validated = IdentityProtocolCaseIn.model_validate(case)
    result = evaluate_identity_protocol_case(validated.model_dump(mode='json'))
    assert result['passed'] is False
    assert 'alg=none' in ' | '.join(result['semantic']['failures'])


def test_saml_either_signature_policy_accepts_assertion_only_signature():
    case = _base('saml')
    case.update({
        'saml_signature_policy': 'either',
        'saml_response_signature_valid': False,
        'saml_assertion_signature_valid': True,
    })
    validated = IdentityProtocolCaseIn.model_validate(case)
    result = evaluate_identity_protocol_case(validated.model_dump(mode='json'))
    assert result['passed'] is True
    assert result['semantic']['saml_signature_policy'] == 'either'


def test_saml_both_signature_policy_rejects_single_signature():
    case = _base('saml')
    case.update({
        'saml_signature_policy': 'both',
        'saml_response_signature_valid': False,
        'saml_assertion_signature_valid': True,
    })
    validated = IdentityProtocolCaseIn.model_validate(case)
    result = evaluate_identity_protocol_case(validated.model_dump(mode='json'))
    assert result['passed'] is False
    assert 'SAML response with invalid signature' in ' | '.join(result['semantic']['failures'])
