from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from fastapi_app.routers.capabilities import CapabilityExecutionRequest, execute_capability


@pytest.mark.asyncio
async def test_kubernetes_execute_rejects_missing_credential_before_asset_or_scan_lookup():
    request = CapabilityExecutionRequest(
        project_id=str(uuid.uuid4()),
        asset_id=str(uuid.uuid4()),
        credential_refs=[],
    )
    with pytest.raises(HTTPException) as exc:
        await execute_capability(
            'kubernetes.read-only-posture',
            request,
            user={'user_id': str(uuid.uuid4())},
        )
    assert exc.value.status_code == 409
    assert 'requires exactly one credential reference' in str(exc.value.detail)
