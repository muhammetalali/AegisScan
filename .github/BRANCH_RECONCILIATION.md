# Branch Reconciliation Record

As of 2026-09-03 the canonical repository has diverged histories.

- `main` contains changes after the previous enterprise-completion merge base.
- `codex/enterprise-completion-2026-09-03` contains the prior enterprise work.
- `codex/reality-gate-2026-09-03` contains the current reality/security boundary hardening.

## Rule

Do not force-reset `main` to a feature branch. Reconcile both histories through a normal Git merge after reviewing conflicts and CI. Preserve valid mainline fixes and enterprise changes.

## Required acceptance

1. Merge must preserve all valid application code from both parents.
2. No duplicate platform root may be introduced.
3. Reality Gate and Proof Matrix must remain active.
4. Security authorization boundary tests must pass.
5. Migration and canonical-platform checks must pass before release.
