# Contributing to AegisScan

## Language and naming

- Use English for Python/TypeScript identifiers, exception classes, API fields, and commit subjects.
- Use Arabic for user-facing logs, CLI messages, and explanatory docstrings when the surrounding module is Arabic-first; otherwise use clear English consistently.
- Keep the product name `AegisScan`. Preserve the import package `aegis` and CLI command `aegis` for Python ecosystem compatibility.
- Add a migration for every Django model change. Never edit an applied migration; create a new one.

## Security and data handling

- Do not commit keys, databases, logs, credentials, dependency folders, or temporary scan output.
- Active validation must be opt-in, isolated, and covered by the existing safety controls.
- New external intelligence integrations must be disabled without an explicit API key and must not block the primary scan.
- Generated frontend `dist/` files are tracked because the deployment image serves them; rebuild them with the documented Node toolchain.

## Before opening a pull request

Run the core tests, Django checks and migration drift check, frontend typecheck/build, and the configured lint/security checks. Include the reason for any environment-only test skip.
