# Defensive adversary simulation

The defensive simulator models attacker objectives as abstract techniques such as credential abuse, privilege-boundary violations, data egress, and build-integrity failures. It evaluates whether the configured controls cover each technique and returns a coverage score, gaps, and remediation recommendations.

It does not contain exploit payloads, generated attack code, evasion logic, commands, target discovery, or network execution. This keeps the digital twin analytical, isolated, and suitable for CI and authorized validation workflows.

Use `DefensiveAdversarySimulator` with a list of technique IDs and either enabled control names or a `{control: bool}` mapping. The result is deterministic and auditable, so it can be included in reports and compared across runs.
