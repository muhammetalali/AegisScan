# AegisScan Lab Modes

AegisScan exposes the same real execution record through two presentation modes.

## Attack Mode

Optimized for operators who need concise operational output: status, discovered services, actionable findings, and the execution ID. Raw evidence and provenance remain persisted server-side but are collapsed from the primary workflow.

## Assurance Mode

Optimized for validation, remediation, and audit: the same execution exposes evidence, timestamps, tool/version, target, raw-output digest, parser status, canonical identity, and provenance relationships.

The modes are presentation/execution-policy layers, not separate scanning engines. A single real execution produces both views. Synthetic findings are forbidden in both modes.

## Capability catalog

| Capability | Category | Status | Primary lab |
|---|---|---|---|
| network_nmap | Network reconnaissance | implemented | Network Lab |
| network_masscan | Network discovery | implemented | Network Lab |
| web_nuclei | Web vulnerability validation | catalogued | Web Lab |
| web_zap | Web application testing | catalogued | Web Lab |
| code_semgrep | Code security analysis | catalogued | Code Lab |
| ad_bloodhound | Active Directory graph analysis | catalogued | AD Lab |
| ad_impacket | Active Directory protocol tooling | catalogued | AD Lab |
| adversary_metasploit | Adversary emulation | catalogued | Attack Lab |
| adversary_caldera | Adversary emulation | catalogued | Attack Lab |
| ai_security | AI/LLM security validation | catalogued | AI Lab |

`catalogued` means the capability is intentionally visible as planned lab capability but is not claimed to have a production-grade executor yet.
