# Web Labs P3: bounded BAC observations

P3 extends the existing `burp.mcp.gateway` capability and scanner task with
`options.mode=lab_sequence`. It executes the pinned `bac-orders-v1` GET recipe;
it does not produce a solved verdict or confirmed finding. P4 owns fixture
verification and the verdict.

## Execution contract

Use the existing capability execute route with a current project-scoped
`provider_decision_ref` and two distinct `credential_refs`. Their vault scopes
must bind the authorized origin and `browser_identity_ref` values `alice` and
`bob`. Only TOKEN and GENERIC target credentials are admitted. An optional
provider authentication reference must be explicitly selected through
`provider_credential_ref` and included in the execution's references. It cannot
also serve as a target identity. The transport probe retains its existing
zero-or-one provider reference contract.

| Step | Identity | Fixed GET path |
|---|---|---|
| owner_baseline | alice | /vulnerable/orders/51 |
| cross_owner_positive | alice | /vulnerable/orders/74 |
| patched_negative | alice | /fixed/orders/74 |
| patched_owner_baseline | bob | /fixed/orders/74 |
| anonymous_negative | anonymous | /vulnerable/orders/74 |
| owner_recheck | alice | /vulnerable/orders/51 |

The server creates request headers in memory. Each authenticated request uses
only its selected identity's bearer material; the anonymous request has none.
Response cookies never become subsequent request headers. Clients cannot
provide a method, path, host, endpoint, headers, raw request or body for a step.
The existing SSE initialize, initialized notification, tools/list and schema
pin checks precede each tools/call. Legacy transport cannot execute the recipe.

## Reservation, commit and recovery

Migration `0049_burp_invocation_claims` adds an internal durable reservation;
it does not add a queue, task or authorization system. A short transaction
revalidates current authority and pins the session, target identity versions,
provider identity and provider authentication version before reserving a call.
It commits before network I/O. Another short transaction revalidates those
bindings and atomically commits the immutable invocation, qualified evidence
and audit record.

A committed idempotency key returns its existing invocation without sending.
An in-flight or indeterminate reservation blocks further requests in that
session. Uncertain calls consume the session budget; there is no automatic
lease expiry, replacement key or retry. A process crash can leave an in-flight
reservation indefinitely. A lost response cannot establish whether the target
processed the request. These rules prevent blind replay; they do not promise
exactly-once external execution.

Cancellation and pause are checked while the local SSE call is pending and
again before evidence commit. Local cancellation closes the call; it cannot
undo a request already received by Burp or the target. Duplicate worker delivery
does not restart a running attempt. Completed/failed attempts admit committed
key reconciliation but cannot send a new request.

## Evidence and validation limits

Each observation records attempt, step, identity, asset, pinned definition and
fixture revision references, HTTP status, request/response hashes, and a bounded
resource projection. Raw requests, responses, tokens and cookies are omitted.
`lab_solved=false`, `verdict=observation_only`, and
`live_fixture_revision_verified=false` remain explicit even when all six steps
complete. Completion means the recipe ran, not that the vulnerability was
confirmed. Preparation stays read-only and reports fixture/runtime verification
as outstanding.

Contract tests use synthetic governance metadata and the real fixture routes
in process. They cover identity isolation, uncertain responses, process crashes,
independent cancellation under a PostgreSQL lock timeout, local SSE cancellation,
credential rotation, terminal delivery and bounded request inputs. They are not
live Burp or vendor provenance claims. Live runtime evidence must be recorded
separately with exact source/image identity and any synthetic approval/authentication
fixtures disclosed. CI additionally builds the retired scanner from scratch
and verifies embedded P3 source and migration hashes offline.
