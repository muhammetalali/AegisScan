# Web Labs P6 — measurement and evidence-driven release

P6 does not add a new execution authority. It measures the already-governed P4 verification and P5 lifecycle surfaces and emits a deterministic release report. Production remains a separate exact-SHA decision.

## Sealed measurement design

The recipe is `aegis.web-labs-p6-recipes.v1` and is committed before held-out execution. The required cases are two baseline cases (vulnerable and patched), two fresh held-out nominal cases (vulnerable and patched), and one held-out disconnect case. Held-out means fresh instance, process, proof and evidence identities created after the plan is sealed and never used for tuning. It **does not** mean an unseen vulnerability family and must not be presented as cross-family generalization.

Every case binds the exact 40-hex source SHA, immutable scanner and fixture image digests, fixture revision, instance/process identities, evidence references, proof SHA-256 and measured resource fields. No percentages or improvements are inferred without those artifacts. The report records medians/totals only from supplied measurements.

## Fail-closed outcome semantics

Nominal vulnerable cases must end `vulnerable`, with a finding and `lab_solved=true`. Nominal patched cases must end `not_vulnerable`, with no finding and `lab_solved=false`. A deliberate transport disconnect must end `indeterminate` with an indeterminate claim, no finding and no solved claim. P6 rejects any report that converts uncertainty into a vulnerability or remediation claim.

Evidence, proof hashes, instance/process identities and case IDs cannot be reused across cases. Baseline and held-out cases must use the same sealed recipe, source SHA, fixture revision and immutable images so the comparison changes only the intended case state.

## Resource and intervention baseline

Each case records wall duration, CPU seconds, peak cgroup memory bytes, external request count and human intervention count. The report exposes baseline and held-out aggregates without claiming a performance improvement threshold that was never established. Operator setup outside the measured attempt must be described in the live closeout; in-attempt intervention is counted explicitly.

## CI and release gate

CI compiles the evaluator and runs its regression suite. CI validates the sealed plan but does not claim to execute live Burp. Live P6 acceptance must run from an exact candidate SHA in the isolated Web Labs topology, preserve raw proof artifacts outside the source tree, and create a SHA-256 closeout manifest. Only after exact-head required CI succeeds may the PR merge. P6 closes only after fresh-main checks succeed on the merge SHA.

## Claim limits

P6 is evidence for `bac-orders-v1` only. It is not production deployment, vendor/provider production approval, an arbitrary PortSwigger Academy solver, or evidence for additional vulnerability families. Expansion requires a separately sealed recipe and evidence set.
