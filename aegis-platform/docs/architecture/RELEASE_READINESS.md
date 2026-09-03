# Release Readiness

AegisScan is not release-ready merely because the repository builds.

A release candidate must provide current-branch evidence for:

- migrations on a fresh database and an already-migrated database;
- authentication, authorization and explicit target scope enforcement;
- real scanner execution through Celery;
- persisted execution status, logs and results;
- finding and Evidence lineage;
- negative authorization and failure paths;
- idempotency and concurrency behavior where state can race;
- API/UI contract parity;
- current E2E validation;
- dependency and generated-artifact hygiene;
- observable health/readiness;
- security regression tests.

Historical evidence may accelerate regression coverage but cannot substitute for current release proof.
