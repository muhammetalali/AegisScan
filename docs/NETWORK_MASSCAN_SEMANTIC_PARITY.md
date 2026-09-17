# Network Masscan Semantic Parity

## Phase objective

This phase admits `network.masscan` as a governed Kali **parity candidate only**. It does not change production provider selection, enable network-profile production dispatch, retire the legacy Masscan binary, or perform a canary/cutover.

The proof is intentionally narrow: the existing production adapter and the Kali `network` profile execute the same bounded Masscan intent against the same deterministic, internal, authorized target. A finding-relevant semantic comparator then proves equality on the identity persisted by the current Masscan ingestion path: `(ip, protocol, port)`.

## Security boundary

The candidate service:

- binds only to `127.0.0.1` and is mounted only by the Reality workflow;
- requires an explicit parity-mode flag and a 64-hex authentication token;
- accepts only capability `network.masscan` and never accepts raw argv, binary paths, or shell input;
- validates the Kali runtime/tool-manifest digest and requires the `network` profile to remain `accepted-no-dispatch`;
- requires the request to match pre-bound `authorization_ref`, `scope_ref`, target, ports, and rate values;
- accepts only IP/network targets and strictly bounded TCP port/range syntax;
- runs with `CAP_NET_RAW` as the sole effective/permitted/bounding Linux capability plus `no_new_privs`;
- fails closed on authorization, scope, target, intent, manifest, capability, token, or privilege drift.

## Semantic parity contract

Raw Masscan output contains volatile fields such as timestamps, TTLs, and response reasons. Those fields are not part of the current persisted finding identity and therefore are deliberately excluded from parity equality.

The canonical semantic snapshot is the sorted, de-duplicated set of:

```text
(ip, protocol, port)
```

A change to any of those fields is parity-significant. Ordering, duplicate records, timestamp, TTL, and reason differences are not.

## Reality proof

`.github/workflows/network-masscan-parity-reality.yml` proves the phase on the exact PR/head SHA by:

1. compiling and testing the comparator and provider contract;
2. building the exact legacy scanner reference and exact governed Kali network image;
3. creating an internal Docker network with no public-internet fixture;
4. executing real legacy Masscan through `scanner_adapters.run_masscan` with `AUTHORIZED_SCAN_TARGETS` bound to the deterministic target;
5. starting the Kali parity candidate in the same scanner network namespace with only `CAP_NET_RAW`;
6. proving rejection of an invalid token and mismatched authorization/scope/target/ports intents;
7. executing the bound Kali Masscan intent and verifying runtime/tool provenance;
8. proving semantic equality and the expected open-port observations;
9. uploading exact-head artifacts plus SHA-256 checksums.

## Explicitly deferred

The following remain separate migration gates:

- Masscan canary routing;
- default-Kali Masscan promotion;
- legacy Masscan retirement/removal;
- any change to production network-profile dispatch.

Each requires its own implementation, fresh CI, evidence, and exact-main verification.
