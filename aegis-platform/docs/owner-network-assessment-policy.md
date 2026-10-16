# AegisScan — APEX V4 Owner Network Assessment Operating Decision

Decision approved by the company owner: 2026-10-16.

This document records the four owner decisions in the existing AegisScan
application. It does not create a second authority, bypass authentication, or
replace the approved production release process.

## 1. One accountable company owner

The authenticated primary company owner is the authority for AegisScan
company/project scanner policy and delegation. The owner's existing superuser
rights and full scan-type catalog are not narrowed by employee preferences.
The owner confirms inclusion of company-owned networks in the company's
authorized assessment scope once; no recurring external paperwork or per-host
approval is required for a target already covered by that approval.

## 2. Portable local-network discovery

When the workstation, Ubuntu VM, Wi-Fi, DHCP address or VMware NAT/Bridged
topology changes, discover the actual active network from the operating system.
Do not bake in an IP, MAC, VMware NIC name, gateway, or subnet. Use the existing
`production_network_identity.py` for Ubuntu routing and Windows physical-adapter
inventory. Distinguish host Wi-Fi from VMware NAT and Docker bridges.

Network discovery reports connectivity only. Connecting to a public/guest/
third-party network is not itself a grant to scan it. A selected IP must remain
within the owner's/company's previously declared assessment scope.

## 3. Select IP → assessment, without recurring approvals

The user selects or pastes an IP, CIDR, URL or asset from an eligible project.
Reuse the existing Assessment Launcher, owner/project access, approved company
CIDR scope, existing governed authorization, capability planner and scanner
providers. On first use of an IP already included in the authorized corporate
scope, record the canonical decision automatically; no per-IP request screen or
second administrator is needed. Do not silently reinstate an asset whose
authorization was expressly revoked or expired.

If a target is not in the approved scope, do not infer permission from a
successful route, a host MAC or a client login IP; let the owner explicitly
extend the company scope once. Use the same authorization ledger and audit
records rather than introducing approval gates or duplicate endpoints.

## 4. Owner-managed staff without repeated administration

The owner provisions staff and assigns roles, project memberships, approved
scan types and capabilities once. Those grants are tied to account/project,
not to the employee's current Wi-Fi IP, physical location or MAC address.
Authorized staff can scan in their approved company projects without a new
approval for each address. Authentication, evidence protection, role grants
and explicit out-of-scope checks remain enforced.

## Implementation and evidence

- Existing backend: `aegis-platform/backend/fastapi_app/routers/assessment_launcher.py`.
- Existing account policy: `aegis-platform/backend/django_project/users/models.py`
  and owner provisioning endpoints.
- Existing network discovery: `aegis-platform/scripts/production_network_identity.py`.
- Existing contract tests: `test_assessment_launcher.py`,
  `test_company_owner_provisioning.py` and
  `tests/test_production_network_identity.py`.
- Existing change review: GitHub PR #410. No duplicate PR or scanner daemon.

**Release gates still required:** exact-SHA CI success, Windows-host discovery
on a real Windows device, verified optional Bridged NIC and firewall exposure,
an approved on-network target scanned by an existing engine, retained evidence,
application/session acceptance and recovery after reboot. PR, CI, merge and
production rollout are distinct states; do not claim deployment until proven.
