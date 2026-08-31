# AegisScan Laboratory Capability Matrix

| Capability | Real tool/framework | Lab | Execution status | Primary output |
|---|---|---|---|---|
| network_nmap | Nmap | Network | implemented | ports/services/versions |
| network_masscan | Masscan | Network | implemented | discovered ports |
| web_nuclei | ProjectDiscovery Nuclei | Web | catalogued | template findings |
| web_zap | OWASP ZAP | Web | catalogued | alerts/passive-active findings |
| code_semgrep | Semgrep | Code | catalogued | code findings |
| ad_bloodhound | BloodHound CE | AD | catalogued | identity graph |
| ad_impacket | Impacket | AD | catalogued | protocol/security observations |
| adversary_metasploit | Metasploit Framework | Attack | catalogued | module/session results |
| adversary_caldera | MITRE Caldera | Attack | catalogued | adversary-emulation observations |
| ai_security | AI/LLM validation adapters | AI | catalogued | model/API security observations |

A catalogued capability is a real technology reserved for a dedicated isolated lab, but AegisScan does not report it as executed until an adapter exists that persists an execution record and its real output. This distinction prevents false readiness and synthetic results.
