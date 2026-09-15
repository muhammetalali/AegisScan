# Recon DNSenum Semantic Parity Gate

## Objective

Prove that `recon.dnsenum` produces semantically equivalent normalized security observations when executed through the legacy native worker and the governed Kali Recon provider.

This stage is evidence-only. It does **not** expand `_PARITY_APPROVED_CAPABILITIES`, does not change production routing, and does not begin M6 Legacy Retirement.

## Safety boundary

The proof uses only the deterministic local DNS fixture under `parity.test` on an isolated Docker network. No Internet target, public DNS zone, or unauthorized asset is scanned.

Both execution paths receive the same authorized target and the same fixture DNS server. The proof compares normalized semantic observations, not raw stdout byte equality.

## Required proof

The exact PR/main SHA must prove all of the following:

1. the DNSenum normalizer contract extracts deterministic DNS hostnames and addresses;
2. semantic parity fails closed on observation drift;
3. the exact legacy scanner image builds successfully;
4. the exact governed Kali Recon image builds successfully;
5. the Kali runtime is bound to immutable deployment trust anchors;
6. the deterministic authorized DNS fixture resolves the expected zone;
7. real `recon.dnsenum` executes through the legacy production runtime;
8. real `recon.dnsenum` executes through the production Kali provider client;
9. both executions produce non-empty normalized observations;
10. both normalized outputs contain the deterministic fixture zone and fixture address;
11. `compare_execution_semantics()` reports semantic equivalence;
12. `default-kali` routing still holds `recon.dnsenum` on legacy until a separate reviewed promotion change expands the approved set;
13. exact-head evidence is uploaded and bound to the tested SHA.

## Promotion rule

Successful parity evidence is necessary but not sufficient for production promotion.

A later, separate change may add `recon.dnsenum` to the parity-approved default-Kali set only after:

- this parity PR is merged;
- fresh-main parity Reality succeeds on the merge SHA;
- the exact-main evidence artifact is inspected;
- production routing, rollback, policy and deployment gates are updated and re-proven.

Until then, `recon.dnsenum` remains legacy-routed in `default-kali` mode.

## Exit gate

This stage closes only when the exact PR head is terminal green, the PR is merged with expected-head protection, fresh-main DNSenum parity Reality is terminal green, and its artifact is bound to the resulting main SHA.
