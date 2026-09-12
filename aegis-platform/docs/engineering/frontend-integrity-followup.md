# Frontend Integrity Follow-up

## Scope

Track frontend integrity issues identified after commit `4689e2b`.

## Findings

- `frontend/src/pages/validations/ValidationCommandCenter.tsx` contains mojibake strings such as `â€”`, `â€¦`, and `â€¢` introduced by an encoding rewrite.
- `frontend/src/pages/validations/ValidationResults.tsx` contains multiple mojibake strings, including corrupted Arabic UI text and typographic punctuation.
- `frontend/src/pages/validations/ValidationResults.tsx` still contains a `Simulation / Demo Data` UI path. This must be traced to its API contract and either removed or explicitly bounded so production validation results never present synthetic data.
- Frontend currently has no discovered test files even though Vitest and React Testing Library are installed.

## Acceptance criteria

1. All affected source files are UTF-8 without BOM and contain no mojibake.
2. No production validation view displays synthetic/demo/fallback result data.
3. Canonical evidence data comes only from the validation API contract.
4. Frontend regression tests cover loading, API error, canonical evidence rendering, and the negative path where evidence is unavailable.
5. `npm run build` succeeds.
6. Frontend test suite succeeds with no project-owned warnings/errors.

## Verification

Backend baseline from `4689e2b` remains:

- `44 passed`
- `pytest -W error::pytest.PytestWarning` passes
- `manage.py check` passes
- canonical evidence table present
- legacy vulnerability evidence table absent
