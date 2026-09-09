# Credential execution runtime contract

This contract is intentionally executable through CI tests, but the text records the invariant for reviewers and future capability adapters.

- Capability requests may provide credential references only through `credential_refs`; credentials are never accepted inside arbitrary options.
- A capability must explicitly declare a non-`none` credential mode before refs are accepted.
- Scheduling authorization records reference-only metadata.
- Scanner workers resolve credentials internally, immediately before execution, using project and actor lineage.
- Native adapters receive ephemeral credential material only through a bounded adapter-specific mechanism; `web.security-headers` uses a short-lived curl config file with 0600 permissions.
- Plaintext material must never appear in task args, scan config, API responses, stdout/stderr, Evidence metadata, execution result data, scan logs, or audit metadata.
- A secret reflected by a target response must fail before Evidence is persisted.
