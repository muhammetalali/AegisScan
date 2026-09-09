from __future__ import annotations

from .native_tool_runtime import NATIVE_TOOL_SPECS, NativeToolSpec, OptionSpec

CAPABILITY_ID = 'api.openapi-runtime-conformance'


def register_api_runtime_capability() -> None:
    if CAPABILITY_ID in NATIVE_TOOL_SPECS:
        return
    NATIVE_TOOL_SPECS[CAPABILITY_ID] = NativeToolSpec(
        capability_id=CAPABILITY_ID,
        binary='aegis-api-runtime-conformance',
        category='api-runtime-security',
        description=(
            'Authorization-pinned, bounded OpenAPI runtime conformance validation '
            'for documented safe GET/HEAD operations only.'
        ),
        scan_type='url',
        asset_types=('api_endpoint',),
        risk='active-low',
        target_kind='url',
        options=(
            ('spec_path', OptionSpec('--spec-path', 'str', '/openapi.json')),
            ('max_spec_bytes', OptionSpec('--max-spec-bytes', 'int', 1048576, 65536, 2097152)),
            ('max_response_bytes', OptionSpec('--max-response-bytes', 'int', 262144, 1024, 1048576)),
            ('max_operations', OptionSpec('--max-operations', 'int', 25, 1, 50)),
            ('timeout_seconds', OptionSpec('--timeout-seconds', 'int', 10, 2, 30)),
        ),
        timeout=600,
        credential_mode='curl-bearer-config',
        credential_kinds=('token', 'api_key', 'generic'),
    )
