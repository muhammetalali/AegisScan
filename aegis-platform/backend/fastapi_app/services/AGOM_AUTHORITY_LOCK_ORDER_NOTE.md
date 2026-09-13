# AGOM Responsibility Authority Lock Ordering

Canonical mutation lock order for governed responsibility writes:

1. Organization
2. OrganizationMembership issuer/target
3. TenantProject when scoped
4. GovernedResponsibilityAssignment when applicable
5. GovernedResponsibilityRevocation / GovernedResponsibilityEvent append

All responsibility mutation paths must use this order to avoid cross-operation deadlocks and to preserve a single per-organization audit-chain serialization point.

This file is a temporary implementation invariant note and should be removed once the service code and Reality tests encode the invariant directly.
