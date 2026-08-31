# Lab Platform Architecture

## Goal

AegisScan treats external security distributions and tools as **capabilities**, not as trusted result generators. A capability must declare its inputs, isolation requirements, authorization requirements, evidence contract, and execution state.

## Current foundation

`fastapi_app.services.lab_registry` is the canonical read-only registry for lab capabilities and lab profiles.

The first lab is `network-lab`:

- Distribution: Kali Linux
- Network discovery: Nmap
- High-speed port discovery: Masscan

The lab is provisioned by an opt-in Compose profile under `packages/labs/network`.

## Control-plane rules

1. Default platform startup must not start security-tool containers.
2. External scanning requires explicit authorization and an explicit target allowlist.
3. The registry may report `catalogued` or `planned`; it must never claim a tool is executable when no hardened executor is registered.
4. Raw tool output, execution metadata, target, authorization context, and parser version must be retained as evidence lineage before a Finding is persisted.
5. Tool errors, blocked access, unsupported inputs, and missing capabilities are states—not synthetic Findings.
6. Findings must remain attributable to a concrete execution and evidence set.

## Expansion path

The same contract is intended for:

- Web: OWASP ZAP, Nuclei and other DAST capabilities.
- Identity/AD: BloodHound CE, Impacket, NetExec and isolated Samba/Windows lab services.
- Adversary emulation: Caldera/Metasploit behind explicit approval and sandbox policy.
- AI security: model/API/RAG validation capabilities with the same evidence contract.

No future capability should bypass the registry, authorization gate, sandbox policy, or provenance pipeline.
