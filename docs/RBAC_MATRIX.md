# AegisScan RBAC Matrix

This document freezes the server-side role/permission contract used by Django REST APIs. The source of truth is `packages/backend/django_project/users/models.py` (`UserRole`, `Permission`, `ROLE_PERMISSIONS`).

## Roles

| Role | Intended authority |
|---|---|
| `super_admin` | Full platform authority |
| `admin` | Platform administration excluding reserved destructive/system privileges |
| `security_manager` | Security operations and team-level security management |
| `security_analyst` | Day-to-day assessment, validation, findings and evidence workflows |
| `developer` | Read-oriented engineering visibility and vulnerability notes |
| `auditor` | Read-oriented assurance, compliance, reporting and audit access |
| `viewer` | Read-only platform visibility |

## Permission Matrix

Legend: `✓` granted, `—` not granted.

| Permission | super_admin | admin | security_manager | security_analyst | developer | auditor | viewer |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| project.create | ✓ | ✓ | ✓ | — | — | — | — |
| project.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| project.update | ✓ | ✓ | ✓ | — | — | — | — |
| project.delete | ✓ | ✓ | — | — | — | — | — |
| project.archive | ✓ | ✓ | ✓ | — | — | — | — |
| project.clone | ✓ | ✓ | ✓ | ✓ | — | — | — |
| asset.create | ✓ | ✓ | ✓ | — | — | — | — |
| asset.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| asset.update | ✓ | ✓ | ✓ | — | — | — | — |
| asset.delete | ✓ | ✓ | — | — | — | — | — |
| scan.create | ✓ | ✓ | ✓ | ✓ | — | — | — |
| scan.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| scan.cancel | ✓ | ✓ | ✓ | — | — | — | — |
| scan.restart | ✓ | ✓ | ✓ | ✓ | — | — | — |
| scan.schedule | ✓ | ✓ | ✓ | — | — | — | — |
| vulnerability.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| vulnerability.update | ✓ | ✓ | ✓ | ✓ | — | — | — |
| vulnerability.assign | ✓ | ✓ | ✓ | — | — | — | — |
| vulnerability.change_status | ✓ | ✓ | ✓ | — | — | — | — |
| vulnerability.add_note | ✓ | ✓ | ✓ | ✓ | ✓ | — | — |
| report.create | ✓ | ✓ | ✓ | — | — | — | — |
| report.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| report.download | ✓ | ✓ | ✓ | ✓ | — | ✓ | — |
| report.compare | ✓ | ✓ | ✓ | — | — | — | — |
| report.share | ✓ | ✓ | ✓ | — | — | — | — |
| compliance.read | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| compliance.update | ✓ | ✓ | ✓ | — | — | — | — |
| knowledge.create | ✓ | ✓ | ✓ | — | — | — | — |
| knowledge.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| knowledge.update | ✓ | ✓ | ✓ | — | — | — | — |
| digital_twin.read | ✓ | ✓ | ✓ | ✓ | — | ✓ | ✓ |
| digital_twin.simulate | ✓ | ✓ | ✓ | — | — | — | — |
| user.create | ✓ | ✓ | — | — | — | — | — |
| user.read | ✓ | ✓ | ✓ | — | — | — | — |
| user.update | ✓ | ✓ | — | — | — | — | — |
| user.delete | ✓ | — | — | — | — | — | — |
| user.manage_roles | ✓ | ✓ | — | — | — | — | — |
| user.manage_permissions | ✓ | — | — | — | — | — | — |
| system.settings | ✓ | ✓ | — | — | — | — | — |
| system.monitor | ✓ | ✓ | — | — | — | — | — |
| system.backup | ✓ | — | — | — | — | — | — |
| api_key.manage | ✓ | ✓ | ✓ | — | — | — | — |
| audit.read | ✓ | ✓ | — | — | — | ✓ | — |

## Enforcement Rules

- Django enforces authorization server-side through `HasPermission` and the centralized role mapping.
- Unauthenticated requests are denied by the permission class.
- Superusers bypass permission checks.
- Team membership management additionally requires a team owner/admin object-level relationship.
- Project, scan and vulnerability resources have object-level membership/ownership guards where applicable.
- A privileged operation must not be protected solely by frontend visibility.

## Required Regression Guarantees

The automated RBAC contract test must continue to verify:

1. Every declared role has an entry in the matrix.
2. Every matrix permission is a declared permission.
3. No role contains duplicate permissions.
4. `super_admin` has the full declared permission set.
5. `viewer` remains read-only for protected domains.
6. `security_analyst` has no user-management or system-administration permissions.
7. `admin` does not receive the reserved `user.delete`, `user.manage_permissions`, or `system.backup` privileges.
8. `auditor` remains unable to mutate protected security state.
