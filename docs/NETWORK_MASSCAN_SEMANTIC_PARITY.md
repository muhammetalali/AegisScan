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
- requires the request to match pre-bound `authorization_ref`, `scope_ref`, target, ports, rate, interface, adapter IP, adapter MAC, and next-hop/router MAC values;
- accepts only IP/network targets and strictly bounded TCP port/range syntax;
- runs with `CAP_NET_RAW` as the sole effective/permitted/bounding Linux capability plus `no_new_privs`;
- fails closed on authorization, scope, target, intent, link identity, manifest, capability, token, or privilege drift.

Masscan's raw-packet receive path also needs the shared network device prepared for packet capture. The Reality proof preserves the production privilege split instead of widening scanner privilege: the existing `scanner-egress` runtime is the trusted network-namespace owner and alone receives `CAP_NET_ADMIN` to put the interface in promiscuous mode and install the egress policy. Both the legacy reference scanner and governed Kali candidate join that namespace with only `CAP_NET_RAW`; neither receives `CAP_NET_ADMIN` or `--privileged`.

The link-layer identity is derived from the deterministic internal Docker namespace and bound identically to both executions. For the same-subnet fixture, the fixture MAC is the explicit next-hop/router MAC. A mutated link identity is rejected by the candidate before Masscan execution.

## Semantic parity contract

Raw Masscan output contains volatile fields such as timestamps, TTLs, and response reasons. Those fields are not part of the current persisted finding identity and therefore are deliberately excluded from parity equality.

The canonical semantic snapshot is the sorted, de-duplicated set of:

```text
(ip, protocol, port)
```

A change to any of those fields is parity-significant. Ordering, duplicate records, timestamp, TTL, and reason differences are not.

## Reality proof

`.github/workflows/network-masscan-parity-reality.yml` proves the exact-head admission and semantic contracts, including the production adapter's validated explicit link arguments and fail-closed candidate binding.

`.github/workflows/network-masscan-real-parity.yml` proves the real dual-run on the exact PR/head SHA by:

1. building the exact legacy scanner reference, exact governed Kali network image, and the existing trusted `scanner-egress` runtime;
2. creating an internal Docker network with no public-internet fixture;
3. starting the deterministic fixture plus the trusted network-namespace owner with `CAP_NET_ADMIN` only at that boundary;
4. deriving and validating the shared interface, adapter IPv4, adapter MAC, and fixture next-hop MAC;
5. executing real legacy Masscan through `scanner_adapters.run_masscan` with `AUTHORIZED_SCAN_TARGETS` and explicit link identity bound to the deterministic target;
6. starting the Kali parity candidate in the same network namespace with only `CAP_NET_RAW` and `no_new_privs`;
7. proving a link-identity mismatch is rejected before scanner execution;
8. executing the bound Kali Masscan intent and verifying authorization, link, runtime, capability, and tool provenance;
9. proving semantic equality and the expected open-port observations;
10. uploading exact-head artifacts, image identities, link-binding evidence, and SHA-256 checksums.

## Explicitly deferred

The following remain separate migration gates:

- Masscan canary routing;
- default-Kali Masscan promotion;
- legacy Masscan retirement/removal;
- any change to production network-profile dispatch.

Each requires its own implementation, fresh CI, evidence, and exact-main verification.
