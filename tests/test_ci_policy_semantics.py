from scripts.ci_concurrency_policy import CANCEL_SAFE, NON_CANCELLABLE, POLICY


def test_release_is_side_effecting_and_validation_is_cancel_safe():
    assert POLICY['supply-chain-release.yml'] == NON_CANCELLABLE
    assert POLICY['domain-contract-reality.yml'] == CANCEL_SAFE
    assert POLICY['frontend-lock-sync.yml'] == CANCEL_SAFE
