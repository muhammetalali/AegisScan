from __future__ import annotations

from .native_tool_runtime import NATIVE_TOOL_SPECS, NativeToolSpec

CAPABILITY_ID = 'cloud.read-only-posture'


def register_cloud_capability() -> None:
    if CAPABILITY_ID in NATIVE_TOOL_SPECS:
        return
    NATIVE_TOOL_SPECS[CAPABILITY_ID] = NativeToolSpec(
        capability_id=CAPABILITY_ID,
        binary='aegis-cloud-security',
        category='cloud-security',
        description=(
            'Credential-scoped, authorization-bound, read-only cloud posture assessment '
            'for AWS accounts, Azure subscriptions, and Google Cloud projects.'
        ),
        scan_type='full_validation',
        asset_types=('cloud_resource',),
        risk='active-low',
        target_kind='cloud',
        timeout=600,
        credential_mode='cloud-credentials-file',
        credential_kinds=('cloud_access_key',),
        credential_required=True,
    )
