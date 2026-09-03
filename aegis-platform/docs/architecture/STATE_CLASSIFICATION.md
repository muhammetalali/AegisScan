# Capability State Classification

Use exactly one highest verified state when reporting a capability:

1. **Not implemented** — no production implementation.
2. **Planned** — intentionally deferred.
3. **Implemented** — code exists and is reviewable.
4. **Integrated** — connected across application boundaries.
5. **Real-data** — consumes and persists real operational data.
6. **Tested** — automated tests cover the relevant behavior.
7. **E2E validated** — the full externally observable workflow passes.
8. **Evidence captured** — proof artifacts and lineage are persisted.
9. **Independently verified** — another reproducible path confirms the result.
10. **Production ready** — all applicable release/security gates pass.

Historical proof must be annotated as historical and must not raise the current capability state.
