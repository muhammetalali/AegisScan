# M3 Dual-run Parity

## Objective

M3 proves that moving a semantic capability from the legacy native worker to the governed Kali execution fabric does not change the security meaning of the result.

The comparison is not byte-level stdout equality. The authoritative comparison is:

`same authorized target + same semantic capability + same normalized options -> normalized observations -> Finding projection`

## Required execution pair

For every capability admitted to M3 cutover proof:

1. resolve the same authorized asset/target;
2. execute the legacy native worker backend;
3. execute the governed Kali profile backend;
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

## Release boundary

Unit/fixture comparator tests are necessary but are **not M3 completion evidence**.

M3 may be declared complete only when a dedicated Reality gate executes both real backends against the same controlled fixture and target, captures both normalized outputs, proves semantic equivalence, and captures exact-head evidence.

The real Kali leg must use the production governed provider trust boundary. Therefore M3 cutover proof is blocked until PR #125 (Kali Recon provenance binding) is synchronized with current main, revalidated on its final exact head, merged, and proven on fresh main.

## Explicit non-goals

M3 does not:

- switch the default provider to Kali;
- remove the legacy worker;
- relax authorization or scope checks;
- compare raw stdout byte-for-byte;
- treat runtime provenance differences as semantic output differences;
- create a second normalizer, Finding lifecycle, or Evidence store;
- start M4 Canary, M5 Default Kali, or M6 Legacy Retirement.

## Exit gate

M3 is complete only after:

- semantic comparator contract tests are green;
- real legacy + Kali executions run on the same deterministic fixture;
- normalized observation parity is green;
- Finding projection parity is green;
- exact PR head is terminal green and behind=0;
- PR is merged with expected-head SHA;
- fresh exact-main Reality is terminal green.
