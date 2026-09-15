# Recon DNSenum Semantic Parity Gate

## Objective

Prove that `recon.dnsenum` produces semantically equivalent normalized security observations when executed through the legacy native worker and the governed Kali Recon provider, and keep that parity proof continuously bound to the production default-Kali routing decision.

The initial parity stage was evidence-only and did not expand `_PARITY_APPROVED_CAPABILITIES`. After that PR merged, fresh-main Reality succeeded on the merge SHA and the exact-main artifact was inspected. A separate promotion change can therefore admit `recon.dnsenum` to the approved default-Kali set without weakening the original evidence boundary.

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
12. `default-kali` routes `recon.dnsenum` to Kali only after the approved-set change is present;
13. the same Reality run proves the promoted path uses `default-kali`, not the engineering-only raw `kali` override;
14. exact-head evidence is uploaded and bound to the tested SHA.

## Promotion rule

Successful parity evidence is necessary but not sufficient for production promotion.

`recon.dnsenum` may be added to the parity-approved default-Kali set only after:

- the parity PR is merged;
- fresh-main parity Reality succeeds on the merge SHA;
- the exact-main evidence artifact is inspected and shows semantic equivalence with no mismatches;
- a separate reviewed promotion change updates routing and its governing Reality assertions;
- the promotion PR proves real DNSenum execution in `default-kali` mode;
- production rollback, provenance and policy gates remain green.

The currently promoted set must remain explicit. Amass and Subfinder stay legacy-routed until they independently satisfy the same process.

## M6 boundary

DNSenum promotion does not retire the legacy worker. `m6_retirement_allowed` remains false while any in-scope Recon capability still depends on legacy routing or while rollback/observation requirements remain open.

## Exit gate

The parity stage is closed because its exact PR head and fresh-main merge SHA both passed real dual-run Reality and the merge-SHA artifact was inspected. The promotion stage closes only when its own exact PR head is terminal green, behind=0, merged with expected-head protection, and followed by fresh-main DNSenum Reality whose artifact proves `production_promotion_performed=true` on the resulting main SHA.
