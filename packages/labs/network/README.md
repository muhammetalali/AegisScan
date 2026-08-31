# AegisScan Network Validation Lab

This lab is an **opt-in** isolated toolbox for authorized network validation and research.

## Components

- Kali Linux rolling userland
- Nmap for controlled host/service discovery
- Masscan for low-rate port discovery
- `aegisscan_lab` bridge network isolated from the default Compose network

## Safety invariants

The lab does not run automatically with the platform. It uses the `security-lab` Compose profile, drops all Linux capabilities except `NET_RAW`, runs as a non-root user, is read-only, and does not mount the host filesystem.

External or third-party targets must never be scanned without explicit authorization. AegisScan's future lab execution control plane must persist the target, authorization context, selected capability, command profile, execution identity, raw tool output, and resulting evidence before a validation can be considered attributable.

No synthetic findings are produced by this lab. A missing tool, missing authorization, or blocked target is an execution/readiness state, not a finding.

## Start locally

From this directory:

```powershell
docker compose --profile security-lab build
docker compose --profile security-lab up -d
docker compose --profile security-lab ps
```

Enter the toolbox:

```powershell
docker compose --profile security-lab exec aegisscan-network-lab bash
```

Verify installed tools:

```bash
nmap --version
masscan --version
```

The container is a toolbox only. Do not treat the presence of a binary as proof that a capability is executable through the AegisScan control plane; the registry deliberately reports Nmap/Masscan as `catalogued` until a hardened executor and provenance writer are connected.
