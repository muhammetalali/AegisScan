# AegisScan Enterprise Proof Matrix

This is the acceptance contract for the canonical platform.

| Capability | Required proof | Current classification |
|---|---|---|
| Authentication | real login/refresh/logout + negative auth tests | Implemented / Tested; current E2E required |
| RBAC / scope | allowed + denied actor/project/target cases | Implemented / Tested; current E2E required |
| Health / readiness | real dependency state from DB + Redis | Implemented; current E2E required |
| Projects | persisted CRUD + authorization + API/UI parity | Integrated; current E2E required |
| Assets | persisted CRUD + identity uniqueness + authorization | Integrated; current E2E required |
| Nmap | real binary execution + findings + Evidence + DB | Historical proof + Implemented; current E2E required |
| Nuclei | real binary/templates + findings + Evidence + DB | Integrated; current E2E required |
| Masscan | real execution + observations + Evidence + DB | Implemented; current E2E required |
| Semgrep | real checkout/path + analysis + findings + Evidence | Implemented; current E2E required |
| Validation | real validation execution and persisted result | Integrated; current E2E required |
| Remediation | actual state change + revalidation + resolution Evidence | Historically proven; current regression required |
| Evidence | lineage, immutability/integrity, finding linkage | Implemented / Tested; current E2E required |
| Intelligence | provider query + provenance + failure behavior | Implemented partially; provider E2E required |
| Risk | evidence-backed calculation from supported inputs | Partial |
| Posture | temporal, evidence-backed posture and delta | Partial |
| Attack Path | graph from persisted assets/findings/trust relations | Partial |
| Compliance | control mapping + evidence + effectiveness | Partial |
| Digital Twin | real state projection + scenario mutation + impact | Partial |
| Notifications / ITSM | external side effect + callback/status + Evidence | Partial |
| WebSocket | live scan lifecycle events from actual worker state | Partial |
| Multi-tenancy | cross-tenant isolation across API/jobs/cache/evidence | Not accepted |
| Production hardening | secrets/TLS/CSP/backups/restore/observability/supply chain | Not accepted |

## Release rule

A capability is not `Completed` or `Production Ready` unless the current canonical branch has reproducible evidence for the required proof level. Historical artifacts are retained only as regression evidence.
