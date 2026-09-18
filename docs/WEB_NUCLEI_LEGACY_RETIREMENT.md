# Governed Kali Nuclei Legacy Retirement

## Scope

This is the M6 retirement phase for `web.nuclei`.

M3 semantic parity, M4 bounded canary, and M5 default-Kali promotion were
independently proven and merged before this phase. M6 removes the same-release
Legacy/Canary production escape hatches and physically removes the local Nuclei
runtime from the production scanner image.

Historical parity/reference images retain the legacy path only so regression
workflows can compare prior behavior. They are not production deployment
targets.

## Production routing

Production is locked to:

- `AEGIS_NUCLEI_PROVIDER=default-kali`;
- `AEGIS_NUCLEI_LEGACY_DISABLED=true`;
- `AEGIS_KALI_NUCLEI_CANARY_BPS=0`;
- loopback-only governed web provider;
- immutable provider image and provenance pins.

When the retirement lock is present:

- Legacy routing is rejected;
- Canary routing is rejected;
- raw `kali` diagnostic mode is rejected;
- provider failure propagates;
- no local Nuclei fallback is attempted.

Rollback is deployment of the previous release. It is not a provider switch
inside the retired release.

## Physical retirement

The production scanner build sets:

- `AEGIS_RETIRE_NMAP=1`;
- `AEGIS_RETIRE_NUCLEI=1`.

The resulting scanner image contains neither:

- `/usr/local/bin/nuclei`;
- `/opt/nuclei-templates`.

Masscan and Semgrep remain present because their migration lifecycles are
independent.

The `legacy-parity-reference` image intentionally keeps Nuclei and templates
for historical parity evidence only.

## Startup preflight

Before the production scanner worker starts,
`nuclei_retirement_preflight` validates:

- retirement lock enabled;
- provider is exactly `default-kali`;
- Canary BPS is exactly zero;
- provider endpoint is explicit loopback HTTP on a high port;
- provider auth token format;
- runner/build provenance pins;
- base/tool/image/runtime SHA-256 pins;
- selected provider image is immutable and matches its expected digest.

Any drift returns a non-zero startup status before scanner tasks can execute.

## Governed provider

The production `kali_web` service is first-class rather than opt-in after M6.

It runs:

- as UID/GID 10001;
- with all Linux capabilities dropped;
- with `no_new_privs`;
- read-only root filesystem;
- bounded PID/memory/CPU;
- in the scanner egress network namespace;
- on loopback port 18770;
- with the pinned web provider runtime and Nuclei templates.

## Reality proof

`Web Nuclei Legacy Retirement Reality` proves on the exact PR/main SHA:

1. production Compose cannot be overridden back to Legacy/Canary;
2. scanner startup includes the M6 retirement preflight;
3. the production scanner image physically lacks Nuclei and local templates;
4. the governed web provider executes real Nuclei against a deterministic
   internal target;
5. runtime provenance and zero-capability boundary are verified;
6. Legacy and Canary routing are rejected when the retirement lock is active;
7. provider outage fails closed while no local Nuclei binary exists;
8. rollback evidence points to the previous release, which still contains the
   legacy runtime;
9. exact-head runtime and contract evidence are uploaded with SHA-256 lineage.

## Exit gate

M6 closes only after:

1. focused retirement contracts pass;
2. real retired-runtime Reality succeeds;
3. full exact-head CI is terminal green;
4. the PR is merged;
5. the exact merged `main` SHA receives fresh-main verification.

Only then is the Nuclei migration lifecycle considered closed.
