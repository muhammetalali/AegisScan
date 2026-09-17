# Governed Kali Semgrep Semantic Parity

## Scope

This phase admits a governed Kali **parity candidate** for `code.semgrep`.

It does **not**:

- change the production Semgrep provider;
- add canary routing;
- promote Kali as the default code-scanning runtime;
- retire or remove the legacy scanner-worker Semgrep path.

The Masscan environment-dependent follow-up remains deferred and is not claimed complete by this phase.

## Production reference

The production reference remains:

`fastapi_app.services.scanner_adapters.run_semgrep`

with finding projection through:

`fastapi_app.tasks.advanced_scans._semgrep_findings`

The persisted finding-relevant fields are:

- `check_id`;
- message/title;
- mapped severity;
- file path;
- start line.

## Governed candidate

The parity candidate runs from the pinned Kali `code` profile with Semgrep 1.177.0.

The control service is loopback-only and fail-closed. The caller cannot choose:

- executable;
- argv;
- filesystem scan path;
- Semgrep rule/config path;
- rule content.

The candidate is bound to:

- capability `code.semgrep`;
- execution reference;
- authorization reference;
- scope reference;
- logical source reference;
- exact source-tree SHA-256;
- exact rule SHA-256;
- bounded timeout.

Runtime requirements:

- non-root;
- zero effective Linux capabilities;
- `no_new_privs`;
- read-only root filesystem in Reality CI;
- source and rule mounts are read-only;
- source trees containing symlinks are rejected;
- no network is required.

## Real dual-run

`Code Semgrep Real Parity` builds:

1. the legacy scanner reference image;
2. the governed Kali `code` profile.

Both run Semgrep on the same deterministic source fixture at the same absolute path using the same repository-owned rule fixture.

Both executions use:

- JSON output;
- `--error`;
- `--no-git-ignore`;
- metrics disabled;
- network mode `none`.

Parity requires:

- matching Semgrep runtime version;
- matching exit code;
- one deterministic finding from each runtime;
- equal normalized finding semantics;
- exact agreement with the current production `_semgrep_findings` projection.

## Exit gate

This phase is complete only when:

1. exact PR HEAD is terminal green;
2. `Code Semgrep Parity Reality` succeeds;
3. `Code Semgrep Real Parity` succeeds;
4. legacy and candidate each execute real Semgrep;
5. authorization/scope/source bindings fail closed on mismatch;
6. source-tree and rule digests are verified before execution;
7. semantic digests are equal;
8. immutable exact-head evidence is uploaded with SHA-256 manifests;
9. the PR is merged;
10. the exact merged `main` SHA receives a fresh post-merge verification.

A separate phase is required before any Semgrep canary, provider cutover, default promotion, or legacy retirement.
