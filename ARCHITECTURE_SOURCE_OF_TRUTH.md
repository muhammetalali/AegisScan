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

## Enforcement

`aegis-platform/backend/scripts/stale_regression_audit.py` fails CI if the retired `packages/` source tree appears on canonical `main`.

No future feature, fix, migration, or test may target the retired tree. Any useful historical behavior must be reimplemented or ported into the canonical `aegis-platform/` architecture and proven through current CI.

## Decision

There is one active application architecture, not two:

`aegis-platform/ = application`

`aegis/ = CLI/client`

`packages/ = archived history only`
