# M6 Legacy Recon Retirement

M6 retires the legacy execution path for the four governed Recon capabilities in the
current production release:

- `recon.amass`
- `recon.dnsenum`
- `recon.fierce`
- `recon.subfinder`

`scanner_worker` remains the authorization-bound control-plane worker for native
capabilities. It no longer contains the four legacy Recon executables in its production
image and can execute those capabilities only through the authenticated, attested Kali
Recon provider.

## Production invariants

1. `AEGIS_RECON_PROVIDER=default-kali` is the only accepted current-release production mode.
2. `AEGIS_RECON_LEGACY_DISABLED=true` is mandatory.
3. `AEGIS_KALI_RECON_CANARY_BPS=0` is mandatory.
4. The production scanner image uses Docker target `production-no-legacy-recon`.
5. Amass, Subfinder, DNSenum, Fierce, and the legacy Amass wrapper are absent from that image.
6. All four capabilities resolve to the governed Kali provider.
7. A provider failure is terminal; it never falls through to a native Recon binary.
8. The Kali image and runtime manifest remain bound to immutable deployment trust pins.

## Rollback boundary

M6 does not keep a hidden in-release legacy route. Operational rollback checks out a
previous release already contained in `main`, restores its compatible `legacy` setting,
and redeploys only when migration safety permits. This preserves a recoverable release
rollback without leaving retired Recon engines reachable in the current production image.

## Evidence gate

M6 is complete only when its exact-head and fresh-main Reality runs prove:

- the production scanner image lacks every retired executable;
- legacy and canary holdback decisions fail closed under the retirement lock;
- all four Recon capabilities select governed Kali;
- a real authorized Recon execution succeeds through the production provider client;
- immutable image/runtime provenance matches the exact source SHA;
- no public-Internet fixture is used;
- all repository-wide mandatory gates are terminal green.
