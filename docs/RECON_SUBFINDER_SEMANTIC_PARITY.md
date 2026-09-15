# Recon Subfinder Semantic Parity

## Objective

This capability first proved real semantic parity between the legacy native scanner
runtime and the governed Kali Recon provider. After exact-head and fresh-main proof, this
separate promotion phase admits `recon.subfinder` to governed `default-kali` routing.

A successful binary exit or empty result set is not parity evidence. Admission requires
non-empty normalized observations produced by the real pinned Subfinder v2.16.0 binary on
both execution planes and a fail-closed semantic comparison.

## Deterministic passive-source fixture

Subfinder is a passive source aggregator, so public Internet results are unsuitable as a
release gate: upstream datasets can change between the legacy and candidate executions.

The Reality workflow therefore preserves the production command while isolating the test
network:

- both execution planes run the real `subfinder -d <target> -silent -duc` command;
- the Docker network is internal and has no external egress;
- a deterministic DNS fixture resolves `api.hackertarget.com` to the local HTTPS fixture
  and resolves the explicitly authorized target `parity.test` to its isolated `/32` test address;
- every other passive-source hostname receives NXDOMAIN;
- an HTTPS fixture presents an ephemeral CA-signed certificate for
  `api.hackertarget.com` and returns deterministic HackerTarget host-search records;
- the ephemeral CA is mounted as the system trust bundle only inside the two parity
  execution containers.

The exact upstream Subfinder v2.16.0 HackerTarget source uses
`https://api.hackertarget.com/hostsearch/?q=<domain>`, so this exercises the real source
adapter and parser without depending on the public service.

## Runtime hardening

Both legacy and Kali adapters include `-duc` (disable update check). The scanner images
already pin Subfinder v2.16.0 at build time; runtime update checks would create an
uncontrolled egress path and cannot change the immutable packaged binary.

## Semantic contract

The production normalizer maps Subfinder hostname output to bounded
`discovered-hostname` observations. Parity compares the normalized observation set and
Finding projection using `aegis.execution-semantic-parity.v1`.

The contract explicitly proves:

1. output ordering is non-semantic;
2. missing hostname observations fail closed with `normalized-observation-drift`;
3. both real executions produce non-empty observations;
4. the expected deterministic hostnames are present on both sides;
5. raw stdout byte equality is not required;
6. the promotion Reality re-runs the same real dual execution using `default-kali` for the
   governed candidate path;
7. runtime provenance and the routing decision are captured in exact-head evidence.

## Promotion rule

Successful parity evidence is necessary but not sufficient for production promotion.
`recon.subfinder` may enter the parity-approved default-Kali set only after the parity PR
is merged, fresh-main Reality succeeds, the exact-main artifact is inspected, and a
separate promotion change re-proves routing, runtime provenance, rollback policy, and the
real dual-run under `default-kali`.

This promotion does not retire the legacy worker. `recon.amass` remains legacy-routed and
M6 Legacy Retirement remains blocked.

## Exit gate

The Subfinder promotion stage closes only when its exact PR head is terminal green,
`behind=0`, the promotion artifact reports `production_promotion_performed=true`, the PR
is merged with expected-head protection, and fresh-main Subfinder Reality and mandatory
release workflows are terminal green on the resulting main SHA.
