# Recon Amass v5 semantic parity gate

## Purpose

This stage repairs and proves the `recon.amass` execution contract before any production routing promotion.

OWASP Amass v5.1.1 `enum` is database-backed: enumeration results are persisted through the Amass engine and are not a stable discovered-name stdout contract. AegisScan therefore must not treat a successful `amass enum` exit with empty console output as parity evidence.

## Governed execution contract

AegisScan packages two distinct artifacts:

- `/usr/local/libexec/amass-real`: OWASP Amass v5.1.1 built from exact upstream commit `79299dce87b0085db0f2f4ef3e9c52cccb49f514` plus the repository-owned authenticated-engine patch.
- `/usr/local/bin/amass`: the AegisScan v5 adapter used by the existing native capability contract.

For the only admitted production enumeration command, the adapter:

1. validates the canonical domain and bounded timeout;
2. obtains a non-blocking single-flight lock because upstream Amass v5 uses fixed engine port 4000;
3. creates a private per-execution graph/log/home/cache tree under `/tmp`;
4. generates a fresh 256-bit engine authentication token that is never sourced from or returned to the scanner request;
5. starts the patched Amass engine;
6. runs `amass-real enum -passive ...` against that authenticated engine and isolated graph;
7. terminates the engine and proves the listener is closed;
8. extracts the real discovered-name result set with `amass-real subs -names ...` from that graph;
9. emits only the bounded discovered-name result stream as capability stdout.

Arbitrary Amass subcommands are rejected by the adapter. Version queries remain available for immutable runtime verification.

## Shared-network security boundary

Production `scanner_worker`, `kali_recon`, and `browser_worker` share the `scanner_egress` network namespace. Upstream Amass v5 binds its engine API on `:4000`; loopback therefore does not provide a worker-to-worker authorization boundary in this topology.

The exact-source build patch requires `AEGIS_AMASS_ENGINE_TOKEN` to be a 64-character lowercase hexadecimal token and authenticates every Amass Engine HTTP and WebSocket API request using `X-Aegis-Amass-Token`. The server validates this token with constant-time comparison. The adapter generates a fresh token per execution and does not expose it in evidence artifacts.

The Kali runtime manifest attests SHA256 digests for:

- the Aegis Amass v5 adapter;
- the patched raw Amass v5 binary;
- the exact engine-auth patch.

## Reality proof

The acceptance workflow must execute real Legacy and real governed Kali Amass v5 against an authorized deterministic Docker-internal fixture.

The fixture:

- uses an `--internal` RFC1918 Docker network;
- resolves only `parity.test` and `api.hackertarget.com`;
- exposes a locally trusted HTTPS HackerTarget-compatible endpoint;
- returns exactly `www.parity.test`, `api.parity.test`, and `mail.parity.test` records;
- provides no Internet egress.

The workflow must separately prove the patched raw engine returns `401` without the token and `200` with the token before running semantic parity.

Both Legacy and Kali outputs must normalize to non-empty observations containing all three expected hostnames. `compare_execution_semantics()` must report semantic equivalence with no mismatches.

## Deliberate holdback

This stage is **evidence-only**. It must not:

- add `recon.amass` to `_PARITY_APPROVED_CAPABILITIES`;
- route Amass through `default-kali`;
- retire the Legacy Recon path;
- enable M6 Legacy Retirement.

With `AEGIS_RECON_PROVIDER=default-kali`, `recon.amass` must remain `legacy` with reason `capability-not-parity-approved` throughout this stage.

Production promotion is a separate change and requires this stage to be merged and independently re-proven on fresh `main` first.
