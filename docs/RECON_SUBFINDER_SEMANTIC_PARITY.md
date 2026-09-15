# Recon Subfinder Semantic Parity

## Objective

This phase proves real semantic parity for `recon.subfinder` between the legacy native
scanner runtime and the governed Kali Recon provider before any routing promotion.

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
- a deterministic DNS fixture resolves only `api.hackertarget.com`;
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
6. no production routing promotion is performed by this phase.

## Governance boundary

This phase does not modify the default-Kali approved capability set. Until a separate
promotion phase is independently reviewed and proven, `recon.subfinder` must remain
legacy-routed under `AEGIS_RECON_PROVIDER=default-kali`.

M6 Legacy Retirement remains blocked.
