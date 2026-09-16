# Recon Amass Semantic Parity and Engine Ownership

## Objective

This stage proves that `recon.amass` can move from the legacy native worker to the
governed Kali Recon provider without changing the normalized security meaning of the
execution and without weakening runtime isolation.

The independent parity gate is complete on exact PR head and fresh main. The reviewed
promotion phase admits Amass to the parity-approved `default-kali` set while retaining
the explicit legacy rollback mode and keeping M6 Legacy Retirement separately gated.

## Why Amass requires a managed runtime

OWASP Amass v5.1.1 is stateful. `amass enum` creates/uses the local collection engine
on TCP/4000 and persists discoveries into the configured OAM graph database. The enum
command itself is not the authoritative discovered-name output stream.

AegisScan therefore must not treat raw `amass enum` stdout as discovery evidence.

The canonical runtime is:

1. require TCP/4000 to be unused before the execution starts;
2. start `amass engine` as an execution-owned foreground child;
3. prove the listening socket inode for TCP/4000 belongs to that child process;
4. create per-execution HOME, XDG, TMP and Amass output/database directories;
5. run passive enumeration against the owned engine and the per-execution database;
6. query the resulting database with `amass subs -names`;
7. expose only that discovered-name stream to Aegis normalization;
8. terminate the engine and remove per-execution state in every exit path;
9. fail closed if TCP/4000 was already occupied or becomes owned by another process;
10. run Amass children with a secret-minimized environment rather than inheriting worker
    database, cloud, proxy or application credentials.

The parent scanner/provider process remains the execution process-group owner, so pause,
resume, cancellation, timeout and worker-loss handling continue to apply to the managed
Amass process tree.

## Network boundary

Amass v5's engine listens on `:4000`. The legacy scanner worker and Kali Recon provider
share the scanner-egress network namespace in production.

The scanner-egress guard therefore installs a netdev ingress rule that drops TCP/4000 on
its external interface. Loopback traffic inside the governed namespace is unaffected.

Reality proof must demonstrate both conditions:

- a process sharing the namespace can reach `127.0.0.1:4000`;
- a peer container cannot reach `<scanner-egress-ip>:4000`.

## Deterministic parity source

The managed runtime supplies a private `-config` file with the
`FQDN->FQDN` transformation. Amass v5.1.1 initializes an empty transformation
map and loads configuration before creating its default files. In a fresh
per-execution HOME, relying on those defaults silently skips discovery
handlers and exports only the seed domain. The explicit configuration is
shared by the legacy and Kali execution paths, enables hostname discovery,
and is removed with the execution state. The parity gate still requires all
three discovered fixture names; returning the seed alone cannot pass.

The reviewed Amass patch also constructs Engine-side session configuration
through `config.NewConfig()` before applying the authenticated client's JSON.
This preserves upstream runtime defaults that are intentionally excluded from
JSON while retaining the exact governed scope and transformations. Reality
evidence requires one authenticated DNSRepo fixture request from each runtime.
The patch also records a `node` relationship when a passive source discovers
a hostname beneath the FQDN it queried. Without that relationship Amass v5
stores the hostname asset but omits it from `amass subs`, hiding successful
passive discoveries from managed runtime output.

Parity uses the real Amass v5.1.1 binary and its real DNSRepo passive plugin.

The isolated fixture provides:

- authoritative DNS for `dnsrepo.noc.org`, `bgp.tools`, and `parity.test`;
- an execution-namespace DNS DNAT rule for Amass v5.1.1 hard-coded public resolver traffic;
- an explicit loopback exclusion so Docker embedded DNS on `127.0.0.11` remains intact for
  normal libc target authorization and container name resolution;
- NXDOMAIN for unrelated public data-source hosts;
- a fixture CA and HTTPS endpoint for the real DNSRepo URL shape;
- three deterministic discovered names:
  - `www.parity.test`
  - `api.parity.test`
  - `mail.parity.test`
- no public-Internet egress.

The Reality gate proves the hard-coded-resolver path with a raw DNS packet sent to
`8.8.8.8:53`; the nftables DNAT must return the deterministic `bgp.tools` answer from
the local fixture. This is distinct from merely proving `getaddrinfo()`, which traverses
Docker's embedded DNS and would not exercise the Amass resolver path.

Legacy and Kali executions share the same isolated DNS/TLS fixture and the same
`timeout_minutes=1` option.

## Semantic comparison

The comparator never compares raw banners, timestamps, execution IDs, image digests or
provider metadata.

It compares the canonical `aegis.native-observations.v1` hostname observations produced
by the existing Amass normalizer. The stage fails closed when:

- either execution exits non-zero;
- either execution produces no normalized observations;
- one of the deterministic fixture discoveries is missing;
- normalized observation digests differ;
- a Finding projection differs;
- the candidate reuses a foreign/stale engine;
- TCP/4000 remains occupied after execution;
- the production ingress boundary exposes TCP/4000 externally.

## CI harness integrity

Readiness and boundary probes are part of the security evidence and must not introduce
false negatives. Under `set -o pipefail`, a pipeline such as
`docker logs ... | grep -q ...` can return exit 141 even when the expected line is
present, because `grep -q` closes the pipe after the first match and the producer
receives SIGPIPE.

Amass Reality therefore captures container logs first and performs the assertion against
the captured value. This preserves fail-closed semantics for the assertion while ensuring
a successful readiness/boundary condition cannot be misclassified as a harness failure.

## Evidence

The exact-head artifact must contain:

- legacy and Kali raw execution envelopes;
- normalized observations for both backends;
- semantic parity report and digests;
- exact tool version and immutable Kali runtime provenance;
- engine teardown proof;
- foreign-engine rejection proof;
- external-interface TCP/4000 denial proof;
- exact Git HEAD.

## Promotion boundary

The completed parity evidence permits the reviewed promotion to:

- include `recon.amass` in `_PARITY_APPROVED_CAPABILITIES`;
- route Amass through governed Kali under `default-kali`;
- preserve `AEGIS_RECON_PROVIDER=legacy` as the explicit emergency rollback;
- preserve fail-closed behavior with no silent provider fallback;
- keep M6 Legacy Retirement disabled until its own retirement proof is complete.

## Exit gate

Amass parity is complete only when:

1. managed runtime unit/contract tests are green;
2. legacy and Kali images package the same managed runtime;
3. real legacy Amass returns non-empty deterministic discovered-name observations;
4. real governed Kali Amass returns semantically equivalent observations;
5. stale/foreign engine reuse is rejected;
6. no Amass engine survives a completed execution;
7. production scanner-egress exposes TCP/4000 only through loopback;
8. exact-head CI is terminal green and branch divergence is zero;
9. exact-main fresh Reality is terminal green and its artifact is inspected.

Amass is no longer legacy-held under default-Kali after promotion; M6 remains closed until the separate retirement phase is proven.
