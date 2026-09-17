# AegisScan Branch Hygiene Governance

## Purpose

Branch hygiene must reduce stale working refs without deleting provenance, active work, safety backups, or diverged history. Deletion is treated as a governed repository mutation, not as a cosmetic cleanup.

## Classification

The controller `scripts/admin/branch_hygiene_admin.py` classifies every live branch against the current default branch and open pull requests.

- `default_branch`: never deleted.
- `historical_archive`: every `archive/*` ref; retained for provenance.
- `safety_backup`: every `backup/*` ref; retained until an explicit backup-retirement decision.
- `active_work`: current head of an open pull request; never deleted.
- `diverged_or_unmerged`: tip is not proven to be an ancestor of the current default branch; retained for review/archive decision.
- `recent_merged`: merged ancestor that has not reached the configured retention threshold.
- `merged_retained`: merged ancestor whose namespace is not approved for automated cleanup.
- `safe_merged_candidate`: aged merged ancestor, no open PR, approved namespace, and therefore eligible only after a second live revalidation.

## Deletion boundaries

Automatic historical cleanup is fail-closed. By default only these namespaces can become deletion candidates:

- `chatgpt-a/*`
- `codex/*`
- `sol-worker/*`

`chatgpt-b/*` is classified but retained by default to avoid cross-workstream collision. It can become eligible only when a manual run explicitly sets `include_chatgpt_b=true`, after the same ancestor/open-PR/SHA checks.

Unscoped refs such as legacy `sol-*` branches are retained unless they are handled in a dedicated archival decision.

## Race protection

An apply operation never trusts a previously generated report as mutation authority. Immediately before deletion it:

1. rebuilds the full plan from current GitHub state;
2. confirms the branch is still not an open PR head;
3. confirms the branch tip is still a merged ancestor of the current default branch;
4. confirms the configured retention age is still satisfied;
5. confirms the exact live ref SHA is unchanged;
6. only then deletes the exact ref.

Any drift fails the operation instead of deleting the ref.

## Existing merged-PR cleanup

`.github/workflows/branch-hygiene.yml` remains the immediate cleanup path for normal same-repository PRs. It deletes the exact merged PR head only when the live head SHA is still equal to the merged PR head SHA, and refuses default/archive branches.

This behavior was proven on the former PR #151 head after merge: the merged branch was removed while the merge commit remained on `main`.

## Reality workflow

`.github/workflows/branch-hygiene-governance-reality.yml` provides:

- exact-head compilation and standard-library unit tests;
- a live read-only inventory on pull requests;
- automatic apply on a qualifying push to `main` after the controller/workflow policy changes, with `chatgpt-b/*` still excluded;
- a retained JSON evidence artifact;
- manual `plan` or `apply` execution;
- explicit `include_chatgpt_b` opt-in for cross-workstream stale merged refs.

The automatic `main` apply is deliberately narrow: it only considers the default approved namespaces and reruns the complete live plan plus exact-SHA validation immediately before each deletion. It therefore cannot delete archives, backups, open-PR heads, diverged refs, recent merged refs, unapproved namespaces, or Chat B branches.

A branch must never be deleted merely because its name looks old. An ancestor proof, open-PR proof, retention check, and exact-SHA revalidation are mandatory.
