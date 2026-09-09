from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.credential_execution import normalize_credential_refs
from fastapi_app.services.native_tool_runtime import NATIVE_TOOL_SPECS


def test_only_declared_capabilities_accept_credential_binding():
    headers = get_capability('web.security-headers')
    assert headers.credential_mode == 'curl-bearer-config'
    assert {'token', 'api_key', 'generic'} <= set(headers.credential_kinds)
    assert NATIVE_TOOL_SPECS['web.security-headers'].credential_mode == 'curl-bearer-config'
    assert get_capability('binary.xxd').credential_mode == 'none'


def test_credential_refs_are_uuid_only_and_bounded():
    first = '11111111-1111-4111-8111-111111111111'
    second = '22222222-2222-4222-8222-222222222222'
    assert normalize_credential_refs([first, first, second]) == [first, second]
    try:
        normalize_credential_refs(['not-a-uuid'])
    except ValueError as exc:
        assert 'UUID' in str(exc)
    else:
        raise AssertionError('non-UUID credential reference was accepted')
    too_many = [f'11111111-1111-4111-8111-11111111111{i}' for i in range(4)]
    try:
        normalize_credential_refs(too_many)
    except ValueError as exc:
        assert 'at most 3' in str(exc)
    else:
        raise AssertionError('too many credential references were accepted')
