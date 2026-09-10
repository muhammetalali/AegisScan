# CI Orchestration Policy

AegisScan distinguishes validation work from publication work.

- Supersedable PR/push validation workflows use a stable group keyed by workflow purpose and PR number or ref, with `cancel-in-progress: true`.
- Operator-triggered validation runs may isolate the group by `github.run_id` when the workflow supports `workflow_dispatch`, so an explicit proof is not accidentally cancelled by a push.
- Release, signing, provenance publication, artifact publication, deployment, migration, destructive restore, and other side-effecting workflows must not be cancelled mid-flight. They use `cancel-in-progress: false` or an equivalent serialized policy.
- A workflow must never share a concurrency group with an unrelated workflow.

The executable policy gate is `tests/test_ci_concurrency_policy.py`, run by `CI Orchestration Reality`.
