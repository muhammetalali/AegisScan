CANCEL_SAFE = 'validation'
NON_CANCELLABLE = 'side-effecting'

POLICY = {
    'domain-contract-reality.yml': CANCEL_SAFE,
    'frontend-lock-sync.yml': CANCEL_SAFE,
    'supply-chain-release.yml': NON_CANCELLABLE,
}
