# AegisScan Lab Target Catalog

## Internal Network Lab

Network: `10.250.10.0/27`

| Address | Target | Service | Capabilities |
|---|---|---|---|
| 10.250.10.10 | network-web-target | nginx/http | network_nmap, network_masscan, web_nuclei, web_zap |
| 10.250.10.11 | network-api-target | python/http :8080 | network_nmap, network_masscan, web_nuclei, web_zap |
| 10.250.10.12 | network-ssh-target | OpenSSH :22 | network_nmap, network_masscan |

The gateway address `10.250.10.1` is infrastructure and is not a catalog target.

## External Nmap Test Target

`scanme.nmap.org`

Allowed capability: `network_nmap`.

It is deliberately not enabled for Masscan or broad/high-rate execution. AegisScan should treat it as a dedicated Nmap test destination rather than as a generic Internet target.
