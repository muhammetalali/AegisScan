from fastapi_app.services.wstg_completion_policy import (
    build_wstg_completion_policy,
    completion_ready,
)

def test_all_97_wstg_tests_have_a_governed_completion_claim_path():
    policy = build_wstg_completion_policy()
    assert policy['total_tests'] == 97
    assert policy['completion_claim_supported_tests'] == 97
    assert policy['gap_native_small_tests'] == 5
    assert policy['gap_native_small_completion_supported'] == 5
    assert policy['observation_alone_is_completion'] is False
    assert policy['completion_is_pass_or_fail'] is False
    assert all(row['completion_claim_supported'] is True for row in policy['rows'])
    assert all(row['verdict_claim_supported'] is False for row in policy['rows'])

def test_native_gap_completion_requires_evidence_and_governed_attestation():
    assert completion_ready(
        classification='GAP_NATIVE_SMALL',
        has_trusted_observation=True,
        governed_attested=True,
    ) is True
    assert completion_ready(
        classification='GAP_NATIVE_SMALL',
        has_trusted_observation=True,
        governed_attested=False,
    ) is False
    assert completion_ready(
        classification='GAP_NATIVE_SMALL',
        has_trusted_observation=False,
        governed_attested=True,
    ) is False

def test_completion_never_replaces_manual_or_conditional_governance():
    assert completion_ready(
        classification='MANUAL_GOVERNED',
        has_trusted_observation=True,
        governed_attested=False,
    ) is False
    assert completion_ready(
        classification='MANUAL_GOVERNED',
        has_trusted_observation=False,
        governed_attested=True,
    ) is True
    assert completion_ready(
        classification='CONDITIONAL_NA',
        has_trusted_observation=False,
        governed_attested=False,
        applicability_attested=True,
    ) is True
