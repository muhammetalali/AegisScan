# Governed Kali Semgrep — Legacy Retirement (M6)

## Scope

M6 closes the `code.semgrep` migration lifecycle after independently proven
semantic parity (M3), bounded canary (M4), and default-Kali promotion (M5).

Production no longer retains a same-release local Semgrep escape hatch.

## Production routing

The retired release is locked to:

- `AEGIS_SEMGREP_PROVIDER=default-kali`;
- `AEGIS_SEMGREP_LEGACY_DISABLED=true`;
- `AEGIS_KALI_SEMGREP_CANARY_BPS=0`;
- `AEGIS_KALI_CODE_URL=http://127.0.0.1:18771`;
- immutable provider image and runtime provenance pins;
- `AEGIS_SEMGREP_WORKSPACE_ROOT=/var/lib/aegis-semgrep`.

With the retirement lock active:

- Legacy routing is rejected;
- Canary routing is rejected;
- raw diagnostic `kali` mode remains unadmitted;
- provider/auth/provenance/runtime failures propagate;
- no local Semgrep retry is attempted.

Rollback means deployment of the previous release, not a provider switch inside
the retired release.

## Physical retirement

The production scanner build sets `AEGIS_RETIRE_SEMGREP=1`.

The resulting scanner image removes:

- the Semgrep console entry points;
- the installed `semgrep` Python package.

The M6 Reality gate verifies both `command -v semgrep` failure and
`importlib.util.find_spec("semgrep") is None`.

Historical `legacy-parity-reference` images intentionally retain Semgrep for
regression and previous-release evidence only.

## Startup preflight

Before the scanner worker starts, `semgrep_retirement_preflight` requires:

- retirement lock enabled;
- provider exactly `default-kali`;
- Canary BPS exactly zero;
- fixed Semgrep workspace root;
- explicit loopback code-provider URL;
- 64-character provider auth token;
- runner/build trust pins;
- immutable base/tool/image/runtime SHA-256 pins;
- selected provider image digest matching the expected image digest.

Configuration drift exits non-zero before Celery can consume scanner tasks.

## Governed code provider

Production makes `kali_code` first-class and removes the opt-in provider
profile from the production boundary.

The scanner owns the snapshot workspace read-write. The provider mounts exactly
the same volume read-only.

The provider remains:

- non-root UID/GID 10001;
- zero Linux capabilities;
- `no_new_privs`;
- read-only root filesystem;
- bounded PID/memory/CPU;
- loopback-only;
- source snapshot bounded to 20,000 files / 256 MiB;
- symlink rejecting;
- SHA-256 bound;
- unable to select caller-controlled binary/argv/workspace root.

## Reality proof

`Code Semgrep Legacy Retirement Reality` proves:

1. exact-head M6 routing and startup contracts;
2. production Compose cannot be overridden back to Legacy or Canary;
3. scanner/provider share one bounded workspace with RW/RO separation;
4. production scanner image physically lacks both Semgrep CLI and Python module;
5. exact governed code-provider image executes real Semgrep offline against the
   repository-owned source/rule fixture;
6. resulting output still projects through the production Semgrep Finding parser;
7. Legacy and Canary routes are rejected while the retirement lock is active;
8. provider outage fails closed while no local Semgrep runtime exists;
9. workspace snapshots are cleaned after execution/failure;
10. rollback evidence points to the previous release containing local Semgrep;
11. exact-head artifacts and SHA-256 evidence are captured.

## Exit gate

M6 closes only after focused contracts and real retirement Reality pass on the
exact PR HEAD, the complete exact-head CI wave is terminal green, the PR is
merged, and the exact merged `main` SHA receives fresh-main terminal-green
verification.
