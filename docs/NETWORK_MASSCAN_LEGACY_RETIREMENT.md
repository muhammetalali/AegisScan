# Governed Kali Masscan — Legacy Retirement (M6)

## Scope

M6 closes the `network.masscan` migration lifecycle after proven semantic
parity (M3), bounded canary (M4), and default-Kali promotion (M5).

Production no longer retains a same-release local Masscan escape hatch.

## Production routing

The retired release is locked to:

- `AEGIS_MASSCAN_PROVIDER=default-kali`;
- `AEGIS_MASSCAN_LEGACY_DISABLED=true`;
- `AEGIS_KALI_MASSCAN_CANARY_BPS=0`;
- `AEGIS_KALI_MASSCAN_URL=http://127.0.0.1:18767`;
- immutable provider image and runtime provenance pins;
- the dedicated `network.masscan` provider.

With the retirement lock active, Legacy and Canary routing are rejected, raw
diagnostic Kali remains unadmitted, and provider/auth/provenance/runtime
failures propagate without local retry.

Rollback means deployment of the previous release, never a provider switch in
the retired release.

## Physical retirement

The production scanner build sets `AEGIS_RETIRE_MASSCAN=1` and removes the
local Masscan executable. Historical `legacy-parity-reference` images retain
Masscan only for regression and previous-release evidence.

## Startup preflight

Before the scanner worker starts, `masscan_retirement_preflight` requires:

- retirement lock enabled;
- provider exactly `default-kali`;
- Canary BPS exactly zero;
- explicit loopback Masscan-provider URL;
- 64-character provider auth token;
- runner/build trust pins;
- immutable base/tool/image/runtime SHA-256 pins;
- selected provider image digest matching the expected image digest.

Configuration drift exits non-zero before Celery can consume scanner tasks.

## Governed Masscan provider

Production makes `kali_masscan` a first-class service. It shares the
`scanner_egress` network namespace and is bounded to:

- exactly `CAP_NET_RAW`;
- no `CAP_NET_ADMIN`;
- `no_new_privileges`;
- read-only root filesystem;
- bounded PID/memory/CPU;
- loopback-only control endpoint;
- the single `network.masscan` capability;
- authenticated, provenance-pinned execution.

`scanner_egress` remains the only owner of `CAP_NET_ADMIN`.

## Reality proof

`Network Masscan Legacy Retirement Reality` proves exact-head policy,
production Compose override resistance, startup-preflight wiring, physical
Masscan binary absence, real governed Masscan execution against a deterministic
internal fixture, expected TCP observations, rejected Legacy/Canary routes,
provider-outage fail-closed behavior, least-privilege runtime, immutable
provenance, previous-release rollback semantics, and SHA-256 evidence capture.

## Exit gate

M6 closes only after focused contracts and real retirement Reality pass on the
exact PR HEAD, the complete exact-head CI wave is terminal green, the PR is
merged, and the exact merged `main` SHA receives fresh-main terminal-green
verification.
