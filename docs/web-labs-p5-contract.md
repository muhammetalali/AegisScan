# Web Labs P5: sealed lifecycle authority

P5 adds bounded lifecycle control around the BAC Web Lab proved in P4. It does
not create a second security plane, a public Docker API, or a new execution
queue. Existing project/tenant authorization, trusted runtime inspection,
Evidence, and the sealed BAC fixture remain authoritative.

## Authority split

Application services own lifecycle records only. The service
`fastapi_app/services/web_lab_lifecycle.py` does not import subprocess or
Docker and receives no Docker socket. Docker create/remove operations exist only
in the trusted host tool `scripts/web_lab_host_lifecycle.py`.

The host tool accepts only an approved lifecycle control container, an immutable
fixture image ID, a bounded shared network namespace, and
`aegis-web-lab-<12 hex>` target names. Created targets are UID 10001:10001,
read-only, non-privileged, `cap-drop ALL`, no-new-privileges, restart disabled,
with bounded CPU/memory/PID limits and no source mount or published port.

After creation, the existing P4 inspector independently hashes the embedded
fixture source and challenges the live process. Registration occurs only after
that inspection passes. The fixture receives no control-plane signing key.

## Lifecycle state and lineage

`WebLabInstance` is the current projection for one generation. A generation is
bound to organization, project, asset, lab definition, fixture revision, variant,
instance UUID, runtime evidence, immutable image ID, exact container ID/name,
target origin, operator, expiry, and optional predecessor.

The first generation cannot supersede another instance. Every later generation
must explicitly supersede the latest generation, and that predecessor must
already be `cleaned`. Generation numbers are monotonically incremented and a
database uniqueness constraint prevents duplicate generation identities.

Supported terminal paths are intentionally narrow:

- `ready -> cleaned` for explicit manual/reset cleanup.
- `ready -> expired -> cleaned` after the TTL boundary.
- `ready -> failed -> cleaned` when reconciliation proves the registered
  runtime is no longer running.
- `cleaned` is terminal and may be replayed idempotently, not reopened.

A cleanup reason of `expired` is admitted only from `expired`; a cleanup
reason of `failed` is admitted only from `failed`. A new failure transition
is admitted only from `ready`.

## Authorization and idempotency

Provisioning requires current project access, active tenant OWNER/MANAGER
membership, the latest still-valid asset authorization decision, an unchanged
authorized target, and the asset authorization projection enabled. Read
operations remain project scoped.

Every lifecycle mutation uses a bounded idempotency key and a canonical request
fingerprint. Reusing the same key with the same request reconciles to the
existing state; reusing it for a different request fails closed.

## Append-only evidence

Each transition creates `WebLabLifecycleEvent` with contiguous sequence,
before/after status, generation, actor, request fingerprint, optional runtime
Evidence, bounded details, previous hash, and entry hash.

ORM update/delete/bulk mutation is denied. PostgreSQL migration
`0051_web_lab_lifecycle` additionally installs
`trg_web_lab_lifecycle_event_immutable`, which rejects direct UPDATE or DELETE.

Before any host mutation, the host orchestrator invokes `verify-chain`. The
service recomputes every entry hash, previous-hash link, sequence, tenant/project
binding, generation, and final state/version. A broken chain blocks Docker
mutation.

## Host operations

- `provision`: create a sealed target, wait for health, run trusted inspection,
  then commit generation 1 or a lineage-bound replacement.
- `reset`: verify the chain and exact container identity, remove that container,
  mark the predecessor cleaned, then provision the next generation.
- `status`: report the chain-verified persisted state and whether the exact
  registered container is present/running.
- `reconcile`: detect stopped/missing runtime; record failed then cleaned, and
  remove a stopped exact-ID container if one remains.
- `expire`: cross the persisted expiry state, remove the exact registered
  container, then record cleaned.
- `reap`: process only bounded READY rows whose expiry is due.
- `cleanup`: explicit exact-ID manual cleanup.

Container-name reuse or container-ID drift is never treated as the registered
runtime; host mutation fails closed.

## Acceptance evidence

Isolated P5 acceptance on 3 October 2026 used a dedicated `burp_p5` PostgreSQL
database and existing isolated Web Lab network namespace, never the production
database. A fresh migration installed the PostgreSQL immutability trigger.

The acceptance exercised three generations:

1. vulnerable generation: provisioned and reset to cleaned;
2. patched generation: provisioned, stopped deliberately, reconciled through
   failed to cleaned;
3. vulnerable generation: provisioned with a short TTL, reaped through expired
   to cleaned.

All three hash chains verified. A direct SQL UPDATE against a lifecycle event was
rejected by the PostgreSQL trigger. No `aegis-web-lab-*` target container
remained after closeout.

The focused lifecycle suite passes seven tests and migration drift reports no
changes. CI must rerun these tests, migration/trigger assertions, and the
host-authority boundary before merge.

## Limits

P5 lifecycle acceptance is isolated engineering evidence. It is not production
deployment, provider production approval, a PortSwigger Academy solver, or proof
for additional vulnerability families. P6 owns measurement and evidence-driven
expansion. Production deployment remains a separate exact-SHA release decision.
