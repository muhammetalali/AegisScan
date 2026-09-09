from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.native_packaging import PACKAGED_NATIVE_CAPABILITIES
from fastapi_app.services.native_tool_runtime import _credential_runtime_args, get_native_tool_spec


def test_kubernetes_capability_contract_is_explicit_and_execution_ready():
    capability = get_capability('kubernetes.read-only-posture')
    assert capability.tool == 'aegis-kubernetes-security'
    assert capability.asset_types == ('kubernetes',)
    assert capability.risk == 'active-low'
    assert capability.credential_mode == 'kubeconfig-file'
    assert capability.credential_kinds == ('kubeconfig',)
    assert capability.credential_required is True
    assert capability.id in PACKAGED_NATIVE_CAPABILITIES


def test_kubeconfig_materialization_is_0600_and_not_inline_in_argv():
    spec = get_native_tool_spec('kubernetes.read-only-posture')
    secret = 'apiVersion: v1\nkind: Config\ncurrent-context: fixture\n'
    args, cleanup = _credential_runtime_args(
        spec,
        ({'kind': 'kubeconfig', 'credential_ref': '00000000-0000-0000-0000-000000000001', 'secret': secret},),
    )
    try:
        assert args[0] == '--kubeconfig'
        assert len(args) == 2
        assert secret not in ' '.join(args)
        path = Path(args[1])
        assert path.is_file()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.read_text(encoding='utf-8') == secret
    finally:
        for value in cleanup:
            Path(value).unlink(missing_ok=True)


def test_kubernetes_capability_rejects_missing_or_wrong_credential_material():
    spec = get_native_tool_spec('kubernetes.read-only-posture')
    with pytest.raises(ValueError, match='requires credential-bound execution'):
        _credential_runtime_args(spec, ())
    with pytest.raises(ValueError, match='requires a kubeconfig credential'):
        _credential_runtime_args(spec, ({'kind': 'token', 'secret': 'abc'},))


def test_existing_bearer_capability_remains_optional():
    spec = get_native_tool_spec('api.openapi-runtime-conformance')
    assert spec.credential_mode == 'curl-bearer-config'
    assert spec.credential_required is False
    assert _credential_runtime_args(spec, ()) == ([], [])
