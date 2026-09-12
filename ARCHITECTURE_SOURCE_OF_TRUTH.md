# AegisScan Architecture Source of Truth

This document defines the canonical repository layout and retires the historical parallel tree.

## Canonical live sources

- `aegis-platform/` is the only canonical enterprise application tree. It owns the active Django, FastAPI, Celery, frontend, deployment, scanner, evidence, governance, and runtime implementation.
- `aegis/` is the installable Aegis CLI/client package exposed by the root `pyproject.toml`.
- `.github/workflows/` contains the canonical CI/reality gates for current release evidence.
- `main` is the canonical release branch. Only results for the exact current `main` HEAD count as release evidence.

## Retired historical layout

The former `packages/` monorepo tree is retired and must not be reintroduced on `main`. Historical paths included `packages/backend`, `packages/core`, `packages/labs`, `packages/platform`, and `packages/web`.

The historical feature branch tip was preserved before retirement:

- Original branch: `feature/enterprise-platform-ui-v2`
- Historical tip: `50698f5dbda1f7eb0a1e9a743e752278323a4c7d`
- Read-only archive ref: `archive/feature-enterprise-platform-ui-v2-50698f5`
- Archive purpose: provenance and forensic comparison only; never a development or release source.

## Historical branch archives

Repository history that previously lived behind hundreds of branch refs has been collapsed into explicit provenance-only archive refs:

- `archive/feature-enterprise-platform-ui-v2-50698f5` -> `50698f5dbda1f7eb0a1e9a743e752278323a4c7d`
- `archive/codex-history-2026-09-12` -> `bd00a9ecfb168590683f75f30f9ea0a503701f19`
- `archive/legacy-working-branches-2026-09-12` -> `15364e35d00563629ff7890b43e371f09c51e5a6`

Exact former branch-name-to-SHA mappings are preserved in:

- `docs/archive/CODEX_BRANCH_ARCHIVE_2026-09-12.json`
- `docs/archive/LEGACY_WORKING_BRANCH_ARCHIVE_2026-09-12.json`

Archive refs are immutable provenance anchors. They are not development branches, merge bases for new work, release branches, or CI evidence.

## Enforcement

`aegis-platform/backend/scripts/stale_regression_audit.py` fails CI if the retired `packages/` source tree appears on canonical `main`.

No future feature, fix, migration, or test may target the retired tree. Any useful historical behavior must be reimplemented or ported into the canonical `aegis-platform/` architecture and proven through current CI.

`.github/workflows/branch-hygiene.yml` deletes the exact internal PR head after a successful merge to `main`, but only when the live branch SHA still equals the merged PR head SHA. `archive/*` and the default branch are never eligible for this deletion path.

## Decision

There is one active application architecture, not two:

`aegis-platform/ = application`

`aegis/ = CLI/client`

`packages/ = archived history only`
