# Governed Kali Nuclei Semantic Parity

## Scope

This phase admits a governed Kali **parity candidate** for `web.nuclei`. It does not change the production provider, does not add canary routing, does not promote Kali as the default, and does not retire the legacy scanner-worker Nuclei path.

## Production reference

The legacy reference remains `fastapi_app.services.scanner_adapters.run_nuclei`:

- authorized `http`/`https` target only;
- server-side scope enforcement;
- pinned Nuclei 3.11.1 runtime;
- repository-owned templates;
- JSONL output;
- redirects disabled;
- no caller-controlled shell or executable.

## Governed candidate

The candidate runs from the `web` Kali profile and is parity-only.

It is bound fail-closed to:

- capability `web.nuclei`;
- execution reference;
- authorization reference;
- scope reference;
- exact target;
- exact deterministic parity-template SHA-256;
- bounded timeout.

Runtime requirements:

- non-root;
- zero effective Linux capabilities;
- `no_new_privs`;
- read-only root filesystem in Reality CI;
- loopback-only control service;
- no caller-provided binary, command, argv, template path, or scanner flags.

## Real dual-run

`Web Nuclei Real Parity` creates an internal Docker network with no public Internet route and serves a deterministic HTTP fixture at `172.32.1.10:8080`.

Both paths execute the same semantic intent:

1. legacy production adapter;
2. governed Kali web candidate.

The comparison is not raw stdout equality. JSONL records are normalized to the fields projected into AegisScan Findings:

- title;
- description;
- remediation;
- severity;
- references;
- CVE IDs;
- CWE;
- matched URL;
- protocol/type;
- template ID;
- matcher name.

The Reality gate also cross-checks normalized observations against the current production Nuclei parser.

## Exit gate

This phase is complete only when:

1. exact PR HEAD is terminal green;
2. both Nuclei parity Reality workflows succeed;
3. real legacy and candidate executions each produce the deterministic finding;
4. semantic digests are equal;
5. authorization/scope/target/template mismatch cases fail closed;
6. exact-head evidence and SHA-256 manifests are uploaded;
7. the PR is merged;
8. the exact merged `main` SHA receives a fresh post-merge proof.

Only after that may a separate Nuclei canary/promotion phase begin.
