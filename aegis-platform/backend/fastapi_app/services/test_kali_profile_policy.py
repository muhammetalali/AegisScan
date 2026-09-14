from __future__ import annotations

import pytest

from fastapi_app.services.capability_registry import CAPABILITIES, get_capability
from fastapi_app.services.kali_profile_policy import CAPABILITY_PROFILE_MAP, PROFILES, resolve_kali_profile


def test_every_registered_capability_has_exact_governed_profile_assignment():
    assert set(CAPABILITY_PROFILE_MAP) == set(CAPABILITIES)
    for capability_id, capability in CAPABILITIES.items():
        assert capability.runner_profile == CAPABILITY_PROFILE_MAP[capability_id]
        assert PROFILES[capability.runner_profile].production_allowed is True
        public = capability.public_dict()
        assert public['runner_profile'] == capability.runner_profile
        # PR-4 defines placement only. Backend cutover is intentionally absent
        # until a later migration PR proves dual-run semantic parity.
        assert 'execution_backend' not in public


def test_full_profile_is_ci_lab_only_and_never_selected():
    assert PROFILES['full'].production_allowed is False
    assert 'full' not in CAPABILITY_PROFILE_MAP.values()


def test_profile_resolution_fails_closed_for_unknown_capability():
    with pytest.raises(ValueError, match='No governed Kali profile assignment'):
        resolve_kali_profile('web.unregistered-tool')


def test_retired_capability_is_not_reintroduced_by_profile_policy():
    assert 'code.terrascan' not in CAPABILITY_PROFILE_MAP
    with pytest.raises(Exception):
        get_capability('code.terrascan')
