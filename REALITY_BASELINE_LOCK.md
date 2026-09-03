# AegisScan Reality Baseline Lock

This document is the execution baseline for the enterprise-completion branch. A capability is considered complete only when the following chain is evidenced:

`Designed -> Implemented -> Integrated -> Real Data -> Tested -> E2E -> Evidence -> Independently Verified`

## Non-negotiable gates

- No UI page may display synthetic security KPIs, fake findings, fake risk scores, or placeholder success states.
- Browser/API transport must cross the centralized frontend API service boundary.
- `/api/v1` domain surfaces must expose versioned, machine-validatable contracts.
- Django migrations must be consistent before tests run and a clean database must migrate without generated drift.
- Scanner execution must be server-side authorized and must persist scanner evidence and finding provenance.
- Retried work must be bounded and idempotent; repeated requests must not create duplicate durable state.
- Tenant-scoped data access must be enforced at the project/organization boundary.
- WebSocket connections are authenticated and resource-scoped.
- Continuous assurance must enqueue real scanner tasks rather than synthesize results.
- Compliance results must derive from persisted assessments/findings/evidence.
- Threat intelligence must retain provider provenance and immutable snapshot integrity.

## Required CI evidence

1. Full UI source audit + TypeScript build.
2. API contract registration/schema tests.
3. Django `check`, `makemigrations --check --dry-run`, and clean `migrate`.
4. Negative-path, idempotency, retry, and concurrency tests.
5. Real Nmap/Nuclei/Masscan/Semgrep execution against authorized CI fixtures.
6. HTTP black-box E2E across authentication, project, scan, finding, evidence, compliance, digital twin, attack path, and intelligence surfaces.
7. Deployment/security checks and Python compilation.

## Framework policy

ISO 27001, SOC 2, NIST, and PCI DSS support is implemented as data-driven framework ingestion and assessment. The repository must not embed unlicensed full copyrighted control catalogs. Production deployments must load the authoritative/licensed catalog through the framework import path and must preserve version/source metadata.
