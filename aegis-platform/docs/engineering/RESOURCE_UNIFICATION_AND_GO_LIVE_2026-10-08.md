# AegisScan resource unification and final launch — 2026-10-08

## Authoritative baseline

- GitHub `main`: `a0a883bbf44c8d2b83d509e343307bca9262a08b`.
- Production deployment at initial audit: [run 37777124788](https://github.com/muhammetalali/AegisScan/actions/runs/37777124788), subsequently **completed successfully**.
- Host: `aegis-prod`. Initial audit checkout `1430c8b9` was superseded by successful controlled deployments; see verified release checkpoint below.
- 139 GitHub workflows, 129 referencing pull_request, 130 push, 115 path-filter, 131 top-level concurrency. 126 configure Python, 75 repeat backend dependency installation, 109 invoke pytest, and 0 declare workflow_call.
- 23 Docker containers running; key infrastructure reported healthy. Docker build cache 24.07 GB (13.5 GB reclaimable), plus 3.087 GB reclaimable image storage. These are estimates, not approved deletions.
- Separate production and resilience GitHub runners are intentional roles; do not treat them as duplicates.
- Existing `governed_work_queue.py` handles governed action claims; do not misinterpret it as a replacement for scanner scheduling. Separate scan launchers exist in asset, scan, capability, orchestrator, enterprise and scheduled execution modules.
- Existing credential/governed execution, authorization, audit and idempotency controls must be reused, not cloned.
- Current issue gates: #349 production Settings/API-key/RBAC acceptance; #343 password recovery, SMTP and approved legal documents; #345 actual enforced second-factor login.

## Execution order — no cross-phase skips

1. **Production release protection:** wait for exact-SHA CI governance and deployment completion, confirm host SHA and E2E evidence. No edits to production checkout while deployment runs.
2. **Responsibility and performance map:** enumerate every API entrypoint, task launcher, Celery Beat schedule, enterprise periodic schedule, runner workflow, and resource owner. Profile CPU/RAM, query counts, queue latency and CI runner-minutes from representative workloads.
3. **Consolidate scanner dispatch inside existing contracts:** one authenticated and authorized execution boundary shared across manual/asset/capability/scheduled operations. Transaction-safe single-flight fingerprint must cover organization, actor/authorization, asset snapshot, target, engine/tool version, options, policy, and scan freshness; preserve explicit rescan and retry semantics, evidence lineage and per-tool isolation.
4. **CI consolidation with parity:** remove redundant environment setup/test invocations by factoring shared steps and applying reliable path filters. Keep all required success contexts stable until governance policy and branch rules are updated and full exact-SHA CI proves equivalent security/functional coverage.
5. **Host/Docker resource efficiency:** right-size Celery workers and image layers only after load measurement. Preserve tools (Kali, Semgrep, Nuclei, Nmap, Masscan), egress protection, Prometheus/alerts, data services and last-known-good rollback.
6. **Functional/UI completion:** test Admin/Operator/Viewer clicks, state persistence, 403, key create/rotate/revoke, URL/IP/CIDR/ZIP authorized E2E, findings, evidence, exports, retry and recovery. Resolve #349/#343/#345 only with actual browser, SMTP and 2FA enforcement proofs.
7. **Controlled launch:** focused tests, full CI, approved merge, exact-SHA production deploy, backup-restore acceptance, signed evidence manifest, release limitations, monitoring and recovery confirmation.

## Safe deletion policy

Candidates after parity and rollback proof: stale Docker build layers and unreferenced images, retired CI definitions, unused canary/legacy configs, duplicate helper entrypoints and inactive temporary files. Never prune persistent volumes, backup/evidence archives, credentials, secrets, the resilience runner, required branch checks or capabilities without explicit replacement evidence.

## First isolated implementation

The existing asset list route materialized all accessible rows before filters/paging. Refactored to push tenancy + filters + pagination to the database for ordinary requests, and stream Python-casefold JSON-tag search preserving existing semantics. Added three DB regression cases. Also suppressed one HTTP refetch per WebSocket frame in ScanProgress, retained terminal/disconnect reconciliation and added frontend tests. Frontend lint, 32/32 Vitest tests, production build, isolated Django/PostgreSQL DB tests and exact-PR-SHA GitHub CI **26/26** passed. PR #351 merged as `04a4fe6bd7ed4e5993f9ba16ce0b8e6504228ed9` and successfully deployed via run `37786798888`.

## Closeout thresholds

Zero unapproved duplicate active scanner runs and zero unauthorized cross-tenant data exposure. No loss of required CI/security checks or scan tools. No evidence/data loss; verified rollback. Measure actual p95 API latency, per-request DB rows, CI runner-minutes, Docker disk use and worker CPU/RAM against a recorded before/after baseline. Do not invent savings percentages.


## Verified release and optimization checkpoint — 2026-10-08

- `main` merge SHA `04a4fe6bd7ed4e5993f9ba16ce0b8e6504228ed9` passed all 27 observed exact-SHA CI runs before controlled rollout.
- Official deployment [run 37786798888](https://github.com/muhammetalali/AegisScan/actions/runs/37786798888) completed **success** with an internal E2E and go-live evidence upload; the artifact is `aegisscan-internal-go-live-04a4fe6bd7ed4e5993f9ba16ce0b8e6504228ed9-37786798888`.
- Actual production Git HEAD equals `04a4fe6bd7ed4e5993f9ba16ce0b8e6504228ed9`; all 23 production containers were running at validation and designated healthchecks were healthy.
- [PR #352](https://github.com/muhammetalali/AegisScan/pull/352) covers optional manual/asset-scan idempotency and defensive denial of password-only JWT issuance for MFA-marked accounts. The initial CI failed because the new route query argument displaced the old positional `user` argument; corrected on commit `fc655cc244238749b440d6e4baf6c9ecab0e676d`. Existing Semgrep authorization plus new scan tests passed **13/13** in isolated PostgreSQL; authentication regression tests with isolated PostgreSQL and Redis passed **10/10**. Final GitHub CI must still pass; do **not** conflate fail-closed with implemented MFA.
- The next CI cache optimization branch `refactor/ci-dependency-cache-20261008` adds `setup-python` pip-cache coverage to **19 existing workflows** that were repeatedly installing backend requirements without cache. This reduces unnecessary package downloads on subsequent cache hits; **no runner-minute or bandwidth saving is claimed before measurement**. No workflow or required check was deleted.
- User-facing blockers remain: issue #343 needs real SMTP/password recovery and approved legal content; #345 needs real MFA challenge enrollment/verification/recovery; #349 needs an authenticated, scoped, expiring and revocable API-key **consumer**, rather than issuance UI alone. Do not close without independent positive/negative tests.
- Existing governed execution, scheduled assurance, manual scan and native-task entrypoints are not yet a proven single broker-delivery outbox; do not claim exactly-once scanner execution or remove the separate worker queues.
