from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RemediationProposal:
    finding_id: str
    action: str
    rationale: str
    validation_plan: tuple[str, ...]
    rollback_plan: tuple[str, ...]
    requires_approval: bool = True


def propose_remediation(finding_id: str, evidence: list[dict[str, Any]], target: str) -> RemediationProposal:
    """Generate a reviewable remediation plan; never executes changes on production assets."""
    signals = ", ".join(str(x.get("type", "evidence")) for x in evidence[:5]) or "correlated security evidence"
    return RemediationProposal(
        finding_id=finding_id,
        action=f"Validate and remediate {finding_id} on {target}",
        rationale=f"Proposal derived from: {signals}.",
        validation_plan=("snapshot or baseline target", "apply candidate change in an isolated twin/sandbox", "run security regression checks", "compare before/after risk and evidence"),
        rollback_plan=("restore the captured baseline", "rerun health and security checks", "record rollback evidence and operator decision"),
    )
