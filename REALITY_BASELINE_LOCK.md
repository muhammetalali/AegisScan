# AegisScan Reality Baseline Lock

This document is the execution baseline for enterprise completion. A capability is complete only when evidenced through:

`Designed -> Implemented -> Integrated -> Real Data -> Tested -> E2E -> Evidence -> Independently Verified`

## Non-negotiable gates

- No UI page may display synthetic security KPIs, fake findings, fake risk scores, or placeholder success states.
- Browser/API transport crosses the centralized frontend API service boundary.
- `/api/v1` domain surfaces expose versioned, machine-validatable contracts.
- Django migrations are consistent before tests and a clean database can migrate from zero.
- Scanner execution is explicitly authorized server-side and persists scanner evidence/finding provenance.
- Retried work is bounded and idempotent; repeated requests do not create duplicate durable state.
- Tenant-scoped data access is enforced at project/organization boundaries.
- WebSocket connections are authenticated and resource-scoped.
- Continuous assurance enqueues real scanner tasks rather than synthetic results.
- Compliance results derive from persisted assessments/findings/evidence.
- Threat intelligence retains provider provenance and immutable snapshot integrity.

## CI evidence required

1. Full UI source audit + TypeScript build.
2. API contract registration/schema tests.
3. Django `check`, `makemigrations --check --dry-run`, and clean `migrate`.
4. Negative-path, idempotency, retry, and concurrency tests.
5. Real Nmap/Nuclei/Masscan/Semgrep execution against authorized CI fixtures.
6. HTTP black-box E2E across authentication, project, scan, finding, evidence, compliance, digital twin, attack path, and intelligence surfaces.
7. Deployment/security checks and Python compilation.

## Framework policy

ISO 27001, SOC 2, NIST, and PCI DSS support is data-driven. The repository must not embed unlicensed full copyrighted control catalogs. Production deployments must load the authoritative/licensed catalog through the framework import path and preserve version/source metadata.
