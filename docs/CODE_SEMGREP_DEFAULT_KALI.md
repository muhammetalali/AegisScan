# Governed Kali Semgrep — Default Provider (M5)

## Scope

M5 promotes the parity-proven and canary-proven `code.semgrep` capability to
Governed Kali as the production deployment default.

This phase does **not** retire the legacy scanner-worker Semgrep adapter.
Physical and policy retirement is a separate M6 phase after fresh-main proof.

## Authoritative routing policy

- deployment default: `AEGIS_SEMGREP_PROVIDER=default-kali`;
- `default-kali` routes every Semgrep execution to the governed Kali code
  provider without cohort hashing;
- canary BPS is fixed to zero for M5 deployment;
- library fallback remains `legacy` when no deployment policy exists so
  non-production development/reference behavior is unchanged;
- `AEGIS_SEMGREP_PROVIDER=legacy` is the explicit administrative M5 rollback;
- `canary` remains available for controlled diagnostics;
- raw `AEGIS_SEMGREP_PROVIDER=kali` remains provider-library diagnostic
  behavior and is not admitted by the production-facing execution layer;
- a selected Kali execution never silently retries through local Semgrep after
  provider, authentication, provenance, control, snapshot, or runtime failure.

## Execution boundary

M5 promotes the exact provider bundle proven in M4. It does not introduce a new
Semgrep runtime.

The governed path keeps:

- Semgrep 1.177.0;
- immutable runtime/image provenance pins;
- authenticated loopback-only control;
- non-root UID 10001;
- zero Linux capabilities;
- `no_new_privs`;
- read-only provider root filesystem;
- bounded PID/memory/CPU;
- source snapshots capped at 20,000 files and 256 MiB;
- symlink rejection;
- exact snapshot SHA-256 binding;
- shared workspace writable only by the scanner and read-only to the provider;
- original source-path restoration before Finding projection;
- pause/resume/cancel semantics;
- no caller-controlled binary, argv, shell, workspace root, or provider
  executable.

## Deployment

`aegis-platform/docker-compose.semgrep-default-kali.yml` is the M5 deployment
overlay.

It configures:

- scanner policy default `default-kali`;
- canary BPS fixed at zero;
- loopback code-provider endpoint on port 18771;
- immutable expected provenance pins;
- fixed shared snapshot workspace;
- the existing governed `kali-code` sidecar under its explicit Compose profile.

Explicit M5 rollback is:

`AEGIS_SEMGREP_PROVIDER=legacy`

There is no automatic fallback from a selected governed execution.

## Reality proof

`Code Semgrep Default Kali Reality` proves on the exact PR/main SHA:

1. static provider-decision and production-admission contracts;
2. M4 canary behavior remains valid;
3. Compose renders `default-kali` as deployment default with BPS zero;
4. explicit `legacy` rollback renders separately;
5. shared workspace RW/RO separation and least privilege remain intact;
6. exact governed code-provider image and runtime trust anchors are derived;
7. a real default-Kali scan executes against deterministic repository-owned
   source/rule fixtures with no network requirement;
8. a real legacy rollback reference executes the same semantic intent;
9. normalized Semgrep findings and the production `_semgrep_findings`
   projection remain equivalent;
10. provider outage fails closed without hidden legacy fallback;
11. explicit legacy rollback still succeeds while the provider is unavailable;
12. exact-head artifacts and SHA-256 evidence are captured.

## M6 boundary

Legacy Semgrep retirement may begin only after this M5 PR is exact-head
terminal green, merged into `main`, and the exact merged `main` SHA receives
fresh-main terminal-green verification.

M6 must physically/policy-retire local production Semgrep rather than merely
hide it behind a provider preference.
