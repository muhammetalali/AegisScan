# Canonical Platform Architecture

## Canonical runtime

The production platform is rooted at `aegis-platform/`.

```text
React / TypeScript
        |
      Nginx
        |
   Django + FastAPI
        |
 Celery / Redis / PostgreSQL
        |
 Scanner adapters / validation / remediation
        |
 Findings / Evidence / Risk / Governance / Audit
```

## Boundary rules

- Django owns durable domain models and transactional state.
- FastAPI exposes the authenticated platform API and delegates durable state to the domain layer.
- Celery executes long-running security operations outside request/response lifecycles.
- Scanner adapters are the only execution boundary for supported external security tools.
- Authorization is checked before enqueueing and again at execution time.
- Evidence is the durable provenance boundary for security observations and validation output.
- Historical artifacts are regression inputs, never live truth.

## Consolidation policy

`aegis/` may remain as a CLI/shared-engine layer only when its code is intentionally consumed by the canonical platform. It must not become a second independent business platform.

Legacy `packages/backend` and `packages/web` implementations are not production targets. Code may be migrated only after review shows that it is unique, current, tested, and compatible with the canonical platform contracts.
