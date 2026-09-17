# Network Nmap Semantic Parity

This phase is the first post-M6 Kali execution-plane expansion and is deliberately **parity-only**.
It does not change production routing.

## Baseline

The current production Nmap path remains:

`run_nmap_scan -> ToolRequest('nmap') -> scanner_adapters.run_nmap -> Nmap XML -> parse_nmap_xml -> Evidence/findings`.

The Kali `network` profile already carries a pinned Nmap binary, but its runtime manifest remains
`accepted-no-dispatch`. That invariant is preserved here.

## Candidate contract

The parity candidate:

- runs only when `AEGIS_KALI_NETWORK_PARITY_MODE=true`;
- binds only to `127.0.0.1` inside the shared scanner network namespace;
- requires a 256-bit hex authentication token;
- accepts only semantic `network.nmap` intent, never raw command/argv/binary fields;
- executes the same fixed Nmap shape as the legacy adapter: `-Pn -sV -oX - -- <target>`;
- uses the pinned `profile-network` Nmap and immutable runtime/tool-manifest provenance;
- mirrors the current production raw-scan requirement with UID 0 but narrows Linux capabilities to `CAP_NET_RAW` only; the candidate does not receive the production worker's `SETUID`, `SETGID`, or `SETPCAP` capabilities;
- rejects any runtime whose production dispatch state is not `accepted-no-dispatch`.

## Reality gate

Completion requires exact-HEAD CI to build both the legacy scanner runtime and the Kali network
profile, execute both against the same deterministic target on an internal Docker network, parse
both XML outputs with the production `parse_nmap_xml` parser, and require equality across the
finding-relevant fields: IP, port, protocol, state, service, product, and version.

The gate must also prove:

- no public-Internet target is used;
- the candidate reports the exact source build commit, pinned Nmap provenance, and Linux capability boundary;
- production network dispatch is unchanged;
- artifacts contain exact HEAD, both raw XML outputs, runtime provenance, and the semantic comparison.

## Non-goals

This phase does **not** promote Nmap to Kali by default, add canary routing, remove Nmap from the
scanner worker, or change Nmap Evidence/finding persistence. Those require a separate promotion
phase after exact-HEAD and fresh-main parity evidence are green.

## Privilege-boundary rationale

The legacy production scanner does not run Nmap with broad container privilege. Its bootstrap hands the
scanner process only `CAP_NET_RAW`, which is required for the production adapter's default privileged
SYN/raw scan semantics. Running the parity candidate with every capability dropped caused Nmap to select
the same privileged scan path but fail before scanning because raw sockets were unavailable.

The parity harness therefore grants exactly `CAP_NET_RAW` and no other capability, sets
`no_new_privs`, and the provider verifies `/proc/self/status` before accepting health or execution
requests. The parity provider remains test-only and is not packaged into the production network profile.
