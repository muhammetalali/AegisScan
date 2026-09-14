# M3 Dual-run Parity

## Objective

M3 proves that moving a semantic capability from the legacy native worker to the governed Kali execution fabric does not change the security meaning of the result.

The comparison is not byte-level stdout equality. The authoritative comparison is:

`same authorized target + same semantic capability + same normalized options -> normalized observations -> Finding projection`

## Required execution pair

For every capability admitted to M3 cutover proof:

1. resolve the same explicitly authorized asset/target;
2. execute the legacy native worker backend;
3. execute the governed Kali profile backend through the production Control Plane provider client;
4. normalize each real tool result with the same production normalizer;
5. compare normalized observations semantically;
6. compare the resulting Finding projection semantically;
7. preserve backend-specific runtime provenance separately as Evidence metadata.

A M3 pass never requires byte-identical raw stdout, execution IDs, timestamps, image digests, provider labels, or list ordering.

## Semantic comparator

`fastapi_app.services.execution_semantic_parity.compare_execution_semantics()` returns `aegis.execution-semantic-parity.v1` with:

- observation digests and counts;
- Finding projection digests and counts;
- explicit mismatch classes;
- one fail-closed `semantic_equivalent` decision.

The comparator canonicalizes dictionary/list ordering recursively but does not delete observation fields. Any normalized security-semantic drift therefore changes the observation digest. Finding projection drift is checked independently.

## Deterministic real dual-run Reality

The dedicated `M3 Dual-run Parity Reality` gate now proves a real execution pair rather than fixture-only comparator behavior.

The gate:

1. checks out the exact PR/main SHA;
2. builds the exact legacy scanner image from `aegis-platform/backend/Dockerfile.django`;
3. builds the exact governed Kali base + `profile-recon` image;
4. derives the Kali deployment trust anchor from the built runtime manifest and immutable image ID;
5. starts `aegis-platform/e2e/m3_dns_fixture.py` as an isolated local authoritative DNS fixture;
6. authorizes only `parity.test` plus the isolated fixture CIDR;
7. executes `recon.fierce` with the legacy production `run_native_tool()` path;
8. starts the real hardened Kali Recon provider from the immutable trust-selected image;
9. independently proves the running provider image equals the Control Plane image trust anchor;
10. executes the same `recon.fierce` capability/target/options through production `execute_kali_recon()`;
11. feeds both real stdout streams into the same production `normalize_enriched_native_output()`;
12. rejects vacuous parity by requiring non-empty DNS observations from both executions;
13. compares normalized observations and the canonical Finding projection with `compare_execution_semantics()`;
14. captures exact-head evidence including legacy tool version, trusted Kali runtime provenance, normalized outputs, semantic digests, counts, and mismatch classes.

The DNS fixture is local and deterministic. It does not depend on a public Internet target, passive provider availability, or mutable external DNS state. Unknown in-zone labels return NXDOMAIN, while stable A/NS/MX/SOA/TXT records provide a bounded discovery corpus.

## Kali provenance dependency

PR #125 (Kali Recon provenance binding) is merged and has fresh exact-main proof on:

`main@94e207210967c520a47aa575be2465f9731ea0b5`

The M3 branch must stay synchronized with that baseline. The Kali leg is not accepted unless:

- the complete Control Plane provenance trust anchor is present;
- the provider runs from the immutable trust-selected image;
- the running container image ID equals `AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST`;
- runtime manifest/tool/build/base identities match the trusted pins;
- `provenance_authority=control-plane-deployment-pins`.

## CI failure correction

The first draft M3 workflow failed before executing comparator tests because pytest-django auto-discovered the Django project without a configured production-grade `SECRET_KEY`.

M3 comparator tests do not require Django. The workflow therefore runs them with an isolated pytest configuration:

`-c /dev/null -p no:cacheprovider --noconftest`

This removes accidental Django bootstrap from a pure semantic-contract test rather than masking the issue with unrelated application secrets.

## Explicit non-goals

M3 does not:

- switch the default provider to Kali;
- remove the legacy worker;
- relax authorization or scope checks;
- compare raw stdout byte-for-byte;
- treat runtime provenance differences as semantic output differences;
- create a second normalizer, Finding lifecycle, Evidence store, or orchestrator;
- use an uncontrolled public target as final parity evidence;
- start M4 Canary, M5 Default Kali, or M6 Legacy Retirement.

## Exit gate

M3 is complete only after:

- semantic comparator contract tests are green;
- real legacy + Kali executions run on the same deterministic authorized fixture;
- both executions produce non-empty production-normalized observations;
- normalized observation parity is green;
- Finding projection parity is green;
- Kali deployment/runtime provenance is independently bound and proven;
- exact PR head is terminal green and `behind=0`;
- PR is merged using the verified expected-head SHA;
- fresh exact-main Reality is terminal green.

Until the final two conditions are satisfied, artifacts deliberately record `cutover_allowed=false`. M4 Canary remains blocked.
