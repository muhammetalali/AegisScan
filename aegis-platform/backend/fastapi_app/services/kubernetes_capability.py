from __future__ import annotations

from .native_tool_runtime import NATIVE_TOOL_SPECS, NativeToolSpec

CAPABILITY_ID = 'kubernetes.read-only-posture'


def register_kubernetes_capability() -> None:
    if CAPABILITY_ID in NATIVE_TOOL_SPECS:
        return
    NATIVE_TOOL_SPECS[CAPABILITY_ID] = NativeToolSpec(
        capability_id=CAPABILITY_ID,
        binary='aegis-kubernetes-security',
        category='kubernetes-security',
        description=(
            'Credential-scoped, authorization-pinned, read-only Kubernetes API posture assessment '
            'for workload isolation and RBAC exposure.'
        ),
        scan_type='url',
        asset_types=('kubernetes',),
        risk='active-low',
        target_kind='url',
        timeout=300,
        credential_mode='kubeconfig-file',
        credential_kinds=('kubeconfig',),
        credential_required=True,
    )
