# Web Labs P4: independent BAC verification

P4 adds `verified_lab_sequence` to the existing `burp.mcp.gateway` capability,
canonical capability execute route, Celery task and `scanners` queue. The legacy
transport probe and six-step observation recipe keep their existing semantics.
No client may supply a request, path, endpoint, header, source revision, verdict
or success flag. The new mode accepts only a project/asset runtime evidence UUID
alongside the existing provider decision and target identity references.

## Trusted runtime inspection

`scripts/inspect_web_lab_runtime.py` is an operator control-plane CLI, not a
scanner tool or HTTP endpoint. It accepts only a dedicated P4 fixture container,
an expected immutable image ID and the trusted fixture source. It requires a
running, nonprivileged, read-only container, UID10001, no source mounts or exposed
ports, all capabilities dropped, no-new-privileges, the fixed Python/uvicorn
entrypoint and the shared lab namespace. It hashes the actual embedded source
independently and challenges the actual local HTTP process. A process restart
gets a new process UUID; provisioning sets a fresh instance UUID.

The internal provisioner registers the inspection in existing Evidence. The
existing deployment evidence HMAC key signs the asset, project, exact origin,
source revision, instance/process UUIDs, variant, container/image IDs and time.
The fixture and Burp receive no signing key. There is no public signing route;
**never sign target- or client-supplied assertions**. Possession of this key is
trusted control-plane authority, not a vendor attestation. The inspector's
expected image ID/source must come from the trusted build, not the target.

Proof lifetime is ten minutes, with no future-dated inspections. Admission,
session creation, each request commit and verdict commit recheck its signature,
project/asset/origin and pinned digest. Key rotation or missing keys fail closed.
The key has no development fallback. The session also retains the existing
authorization/provider and credential-version checks.

## Eight fixed GET steps and independent verdict

The verifier surrounds the existing six BAC requests with two anonymous
`/__lab__/identity` requests. The challenges derive from the immutable session
UUID and distinct step IDs. Both responses must match the independently signed
instance, process, source revision and variant. A target self-report alone is
insufficient. The parser rejects duplicate JSON fields and saves only bounded
facts and hashes; authentication material and raw request/response bodies are
not persisted.

The verifier reads eight committed, evidence-qualified immutable invocations,
checks exact ordering, request/response hashes, evidence payload integrity and
the attempt/session/project/asset/authorization lineage. In-flight or uncertain
claims, missing observations or a different process cannot produce success.
It sends no additional request and runs only in the short final transaction.

The positive condition is Alice reading Bob's exact order and tenant, while
Alice's owner baseline/recheck, Bob's patched owner baseline, the patched denial
and the anonymous denial all match the pinned contract. Status200 alone is not
a positive condition. A sealed patched twin returning cross-owner404 with the
same valid controls produces `not_vulnerable`, never `lab_solved=true`.
Missing/conflicting controls produce `indeterminate`, not a false positive or
proof of remediation. Scan completion means the recipe/verifier ran; consult
the explicit verdict and reason codes.

## Existing evidence and confirmation contracts

The final verdict uses existing Evidence and Evidence Qualification. A positive
verdict creates one OPEN Vulnerability and a completed authorized ValidationRun
with `validation_output` evidence; the existing Finding Confirmation service/API
can review it. The worker never self-confirms a finding, bypasses responsibilities
or completes a WSTG methodology. Fixture success, finding evidence and governed
confirmation remain separate states. Negative/indeterminate verdicts create no
finding or confirmation. Atomic commit and a signed deterministic verdict record
prevent duplicates and forged reconciliation results.

Runtime/verification Evidence is append-only in ORM and PostgreSQL, alongside
the existing Burp evidence protections. No new Evidence, Permission, Credential,
queue or dispatcher system is introduced. The Docker-aware inspector stays on
the trusted host; application workers receive no Docker socket.

## Acceptance and limits

The guarded `e2e/live_burp_lab_verification.py` requires the isolated P4 database,
Redis database1 and an explicit integration flag. Provider approval metadata and
authenticated principals are synthetic acceptance fixtures. It exercises real
canonical scheduling, broker, worker, Burp, sealed target and durable records.
An optional distinct synthetic reviewer exercises the existing governed
confirmation API with project-scoped FINDING_CONFIRMER responsibility.

Acceptance must include a positive fixture, a fresh independent instance and a
patched twin, plus missing/tampered/stale proof, changed process, false controls
and evidence immutability tests. A cold scanner build verifies20 embedded source
hashes, the migration, retired tools and canonical producer. No production
provider approval, deployment, arbitrary external/Academy solver or XSS solver
is implied. Further families require their own proven actions and verifier.
