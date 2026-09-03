# Reality-First Delivery

Every implementation must answer four questions before it can be called complete:

1. **What is the source of truth?**
2. **What actually executed?**
3. **What persisted as Evidence and audit lineage?**
4. **What independently reproduced the result, including the failure path?**

Security work must be evaluated as one system:

`Adversary → Attack Surface → Architecture → Controls → Telemetry → Detection → Response → Evidence → Risk → Governance → Engineering → UX → Continuous Validation`

A UI representation is a projection of state; it is never the authority for security state. Requests express intent; persisted authorization and execution results determine authority and outcome.
