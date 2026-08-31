# Lab Platform Architecture

## Goal

AegisScan treats external security distributions and tools as **capabilities**, not as trusted result generators. A capability must declare its inputs, isolation requirements, authorization requirements, evidence contract, and execution state.

## Current foundation

`fastapi_app.services.lab_registry` is the canonical read-only registry for lab capabilities and lab profiles.

The first lab is `network-lab`:

- Distribution: Kali Linux
- Network discovery: Nmap
- High-speed port discovery: Masscan

The network tools are real executors behind an opt-in Compose profile. A Celery worker calls the isolated lab executor over its dedicated lab network; the lab executor runs the actual binary and returns raw output plus parsed observations.

## Running the real network lab

Create `AEGIS_LAB_EXECUTOR_TOKEN` in `packages/platform/.env` with a high-entropy secret. Then from `packages/platform` run:

```powershell
docker compose -f docker-compose.yml -f docker-compose.network-lab.yml --profile security-lab build aegisscan-network-lab
docker compose -f docker-compose.yml -f docker-compose.network-lab.yml --profile security-lab up -d aegisscan-network-lab
```

Network-tool validations must explicitly set `authorized: true` and include an exact `lab_target_allowlist` entry matching the requested target. The adapter refuses execution without both controls.

Example validation engine names are `network_nmap` and `network_masscan`. Nmap supports `connect-discovery` and `service-enumeration`; Masscan is intentionally limited to the `low-rate-discovery` profile and ports 1-1024 at rate 100.

## Provenance contract

For every successful network execution AegisScan persists:

- requested target and authorization/allowlist match;
- exact command argv returned by the lab executor;
- tool version and executor image identifier;
- execution identifier and start/end timestamps;
- return code, stdout, stderr and SHA-256 of stdout;
- parsed observations used to create Findings;
- an Evidence identifier linking the execution to every derived Finding.

The parser never invents an open port. A Finding is emitted only from an observation parsed from the actual tool output. Tool failures, authorization blocks, invalid scope and unavailable executor state remain execution errors and never become synthetic Findings.

## Isolation rules

1. Default platform startup must not start security-tool containers.
2. External scanning requires explicit authorization and an exact target allowlist.
3. The network-tool worker does not execute shell strings; commands are fixed argv arrays assembled by the lab agent.
4. The lab executor runs non-root, drops all Linux capabilities except `NET_RAW`, uses read-only storage and has no host filesystem mount.
5. CIDR targets larger than 256 addresses and hostnames resolving to more than 16 addresses are rejected.
6. Raw tool output and execution metadata are part of the evidence lineage before a Finding is persisted.
7. Tool errors, blocked access, unsupported inputs and missing capabilities are states—not synthetic Findings.

## Expansion path

The same contract is intended for:

- Web: OWASP ZAP, Nuclei and other DAST capabilities.
- Identity/AD: BloodHound CE, Impacket, NetExec and isolated Samba/Windows lab services.
- Adversary emulation: Caldera/Metasploit behind explicit approval and sandbox policy.
- AI security: model/API/RAG validation capabilities with the same evidence contract.

No future capability should bypass the registry, authorization gate, sandbox policy, or provenance pipeline.
