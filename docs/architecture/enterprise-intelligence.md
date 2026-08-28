# Enterprise Intelligence Architecture

## Fusion
`FusionEngine` converts heterogeneous provider observations into one explainable confidence score. Confidence is not exploitability and never authorizes active testing.

## Attack Surface
`AttackSurfaceProfiler` accepts normalized observations from an authorized Nmap/Masscan integration and computes added/removed services. Scanner execution is intentionally kept behind an approval-controlled adapter so the core platform cannot accidentally probe arbitrary targets.

## Remediation Validation
`RemediationValidationSuite` is fail-closed: a candidate requires an approval ID and every registered validation check must pass. Nuclei/Semgrep/Trivy can be connected as validation adapters in a sandbox or digital twin.

## Intelligence providers
Recommended provider adapters include NVD, OSV, CISA KEV, EPSS, GitHub Advisory Database, Red Hat advisories, Snyk, Exploit-DB, GreyNoise, Shodan and Censys. Every adapter must declare provenance, collection time, terms/rate limits and credential source.

## Tiers
- Tier 0 / Security Engineer: operational security controls and full investigation capability, subject to approval policy.
- Tier 1 / Developer: reports, remediation proposals and developer-safe validation results.
- Tier 2 / Auditor: read-only evidence, audit and report export.

## Safety boundary
External intelligence and scanning are evidence inputs. AegisScan does not infer authorization from a discovered asset. Active testing must be explicitly scoped, approved and executed in the designated validation environment.
