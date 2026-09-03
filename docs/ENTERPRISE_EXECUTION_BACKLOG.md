# Enterprise Execution Backlog

This backlog is derived from the project reality standard. It is intentionally not a claim that the listed capabilities are complete.

## P0 — Truth and consolidation

- Reconcile `main` with `codex/enterprise-completion-2026-09-03` without force-resetting valid mainline changes.
- Prove one canonical production tree: `aegis-platform/`.
- Inventory and retire duplicate/legacy platform implementations only after uniqueness review.
- Remove tracked generated artifacts from source control where not explicitly required.
- Consolidate duplicate proof JSON artifacts into canonical evidence references.
- Run fresh-database migration and drift gates.
- Run full API contract and UI route audit.

## P1 — Current acceptance

- Current authentication/RBAC/target-scope E2E.
- Current Nmap, Nuclei, Masscan and Semgrep E2E with Evidence persistence.
- Negative authorization, malformed-input, failure, timeout and dependency-failure tests.
- Idempotency and concurrency tests for scans, evidence and remediation.
- Current remediation/revalidation proof.

## P2 — Intelligence and risk

- Current NVD, OSV, CISA KEV and EPSS provider E2E.
- Provider provenance, cache, throttling and fail-closed behavior.
- Evidence-backed risk calculation and posture evolution.

## P3 — Security operations

- Attack-path graph, blast radius, evidence graph and investigation workflow tied to persisted state.
- Detection/telemetry integration and measurable control effectiveness.
- Real-time worker lifecycle events through WebSocket.

## P4 — Governance and scale

- Evidence-mapped compliance controls.
- Tenant isolation tests across API, queues, cache, evidence, files and audit.
- Enterprise audit and segregation-of-duties controls.

## P5 — Integrations and production hardening

- ITSM, notification, SIEM/SOAR, cloud, Git, SBOM, container and registry integrations.
- Secrets management, TLS, security headers, observability, backups/restore, dependency pinning, image scanning and supply-chain controls.
