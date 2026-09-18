# Governed Kali Semgrep Canary

## Scope

This is the M4 bounded-canary phase for `code.semgrep`.

M3 semantic parity was independently proven and merged before this phase. M4 does not promote Kali as the default Semgrep provider and does not retire the legacy scanner-worker Semgrep path.

The production execution layer admits:

- `legacy`;
- `canary`.

Raw diagnostic `kali` mode remains library-only and is rejected by the production execution wrapper.

## Deterministic bounded routing

Canary assignment is deterministic from:

`routing_schema + capability_id + routing_key`

The routing key is the scan ID.

The canary range is bounded to 0-2500 basis points:

- `0` = explicit rollback to legacy;
- `1..2500` = selected Kali cohort plus legacy holdback cohort;
- values above 2500 fail closed.

A selected Kali execution never retries through legacy when the provider, runtime attestation, authorization, control channel, or Semgrep process fails.

## Source snapshot boundary

Code cannot be referenced by an arbitrary path inside the Kali provider because the provider runs in a separate container filesystem.

The scanner therefore creates a bounded immutable snapshot in:

`/var/lib/aegis-semgrep/<64-hex-snapshot-id>`

The scanner has read/write access to the workspace. The code provider mounts the same volume read-only.

Snapshot policy:

- maximum 20,000 files;
- maximum 256 MiB;
- regular files only;
- symlinks rejected;
- SHA-256 tree digest computed after staging;
- random 256-bit snapshot ID;
- provider verifies the complete tree digest before execution;
- provider execution target is derived from the snapshot ID and internally generated `source_entry`;
- caller cannot choose a filesystem root, executable, argv, or Semgrep config;
- snapshot is removed after the selected execution completes or fails.

Single-file assets preserve file-only scan semantics through `source_entry`.

## Finding-path preservation

The Kali provider necessarily scans the internal snapshot path.

Before the result reaches `_semgrep_findings`, the scanner execution wrapper rewrites every provider result path from the bound snapshot root back to the original authorized source path.

A provider result outside the bound snapshot is rejected.

This keeps persisted Finding semantics equal across legacy and selected Kali cohorts:

- check ID;
- message;
- severity;
- file path;
- line.

## Governed code provider

The provider is built from the pinned Kali `code` profile and enables semantic dispatch only for:

`code.semgrep`

Runtime requirements:

- Semgrep 1.177.0;
- non-root UID;
- zero effective/permitted/bounding/inheritable/ambient Linux capabilities;
- `no_new_privs`;
- read-only root filesystem;
- bounded PID/memory/CPU;
- loopback-only HTTP control surface;
- authenticated requests;
- exact runtime/build/base/tool/image/runtime-manifest provenance pins;
- scanner-owned source workspace mounted read-only;
- deployment-owned Semgrep config.

The provider supports scan pause/cancel through the same execution-control model used by other governed providers.

## Deployment

`docker-compose.semgrep-canary.yml` is opt-in.

It adds:

- bounded Semgrep provider policy to `scanner_worker`;
- shared `semgrep_workspace` volume;
- governed `kali_code` provider under the `kali-code` profile.

The scanner bootstrap initializes only the fixed path:

`/var/lib/aegis-semgrep`

before dropping privileges to UID 10001.

## Reality proof

`Code Semgrep Canary Deployment Reality` proves:

- rendered canary policy;
- shared workspace is scanner-RW/provider-RO;
- provider is loopback-only;
- provider is non-root;
- all Linux capabilities are dropped;
- `no_new_privs`;
- bounded resources;
- no exposed provider port;
- immutable provenance inputs are wired;
- workspace bootstrap cannot target an arbitrary path.

`Code Semgrep Canary Reality` proves:

1. exact-head contract tests;
2. deterministic selected and holdback cohorts;
3. real legacy Semgrep execution;
4. real governed Kali Semgrep execution;
5. identical exit-code behavior;
6. finding-semantic equivalence;
7. original file-path equivalence;
8. zero-BPS rollback to legacy;
9. selected provider outage fails closed without legacy fallback;
10. workspace cleanup after execution;
11. exact-head artifacts and SHA-256 evidence.

## Exit gate

M4 closes only after:

1. both Semgrep canary Reality workflows succeed;
2. full exact-head CI is terminal green;
3. the PR is merged;
4. exact merged `main` receives fresh-main verification.

Only after M4 closes may a separate M5 default-Kali promotion begin.
