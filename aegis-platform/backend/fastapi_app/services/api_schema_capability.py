from __future__ import annotations

from .native_tool_runtime import NATIVE_TOOL_SPECS, NativeToolSpec, OptionSpec

CAPABILITY_ID = 'api.openapi-contract-security'


def register_api_schema_capability() -> None:
    if CAPABILITY_ID in NATIVE_TOOL_SPECS:
        return
    NATIVE_TOOL_SPECS[CAPABILITY_ID] = NativeToolSpec(
        capability_id=CAPABILITY_ID,
        binary='aegis-api-schema-security',
        category='api-security',
        description='Bounded defensive OpenAPI/Swagger contract security analysis for an authorized API origin.',
        scan_type='url',
        asset_types=('api_endpoint', 'website'),
        risk='active-low',
        target_kind='url',
        options=(
            ('spec_path', OptionSpec('--spec-path', 'str', '/openapi.json')),
            ('max_spec_bytes', OptionSpec('--max-spec-bytes', 'int', 1048576, 65536, 2097152)),
            ('timeout_seconds', OptionSpec('--timeout-seconds', 'int', 10, 2, 30)),
        ),
        timeout=90,
    )
