from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


AGOM_CONTRACT_VERSION = 'agom.v1'


class ActorLayer(StrEnum):
    OPERATE = 'operate'
    GOVERN = 'govern'
    ASSURE = 'assure'


class ProjectionKind(StrEnum):
    LIFECYCLE = 'lifecycle'
    OUTCOME = 'outcome'
    POSTURE = 'posture'
    GOVERNANCE = 'governance'
    ASSURANCE = 'assurance'


class ActionMode(StrEnum):
    ENABLED = 'enabled'
    BLOCKED = 'blocked'
    HIDDEN = 'hidden'


class GateState(StrEnum):
    PASS = 'pass'
    FAIL = 'fail'
    BLOCKED = 'blocked'
    NOT_APPLICABLE = 'not_applicable'


class GateType(StrEnum):
    AUTHORIZATION = 'authorization'
    EVIDENCE = 'evidence'
    VALIDATION = 'validation'
    PUBLICATION = 'publication'
    CLOSURE = 'closure'
    EXPIRY_REVIEW = 'expiry_review'
    LIVE_ACCEPTANCE = 'live_acceptance'
    INDEPENDENT_VERIFICATION = 'independent_verification'


class EntityRef(BaseModel):
    model_config = ConfigDict(extra='forbid')

    entity_type: str
    entity_id: str
    tenant_id: str | None = None
    project_id: str | None = None


class ProjectionSnapshot(BaseModel):
    model_config = ConfigDict(extra='forbid')

    lifecycle: str | None = None
    outcome: str | None = None
    posture: str | None = None
    governance: str | None = None
    assurance: str | None = None
    version: int | None = Field(default=None, ge=0)


class GateResult(BaseModel):
    model_config = ConfigDict(extra='forbid')

    gate: GateType
    state: GateState
    reason_code: str = ''
    reason: str = ''
    missing_requirements: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    policy_version: str = ''
    evaluated_at: datetime | None = None


class ActionContract(BaseModel):
    model_config = ConfigDict(extra='forbid')

    action_id: str
    entity_type: str
    intent: str
    allowed_states: list[str]
    actor_layers: list[ActorLayer]
    allowed_roles: list[str]
    required_responsibilities: list[str] = Field(default_factory=list)
    required_gates: list[GateType] = Field(default_factory=list)
    evidence_requirements: list[str] = Field(default_factory=list)
    sod_rules: list[str] = Field(default_factory=list)
    expected_version_required: bool = True
    idempotency_required: bool = True
    time_aware: bool = False
    side_effects: list[str] = Field(default_factory=list)
    resulting_projection: dict[str, str] = Field(default_factory=dict)
    audit_event: str
    policy_version: str


class CapabilityItem(BaseModel):
    model_config = ConfigDict(extra='forbid')

    action_id: str
    mode: ActionMode
    intent: str
    evaluated_actor_layer: ActorLayer | None = None
    reason_code: str = ''
    reason: str = ''
    missing_requirements: list[str] = Field(default_factory=list)
    gate_results: list[GateResult] = Field(default_factory=list)


class CapabilityManifest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    contract_version: Literal['agom.v1'] = AGOM_CONTRACT_VERSION
    entity: EntityRef
    projection: ProjectionSnapshot
    actor_layer: ActorLayer
    actor_role: str
    actor_responsibilities: list[str] = Field(default_factory=list)
    capabilities: list[CapabilityItem]
    generated_at: datetime


class AuthoritativeCapabilityManifest(BaseModel):
    """Server-derived entity capability projection.

    Unlike the legacy generic manifest builder, this contract deliberately has
    no caller-selectable actor layer. Each action is evaluated in one of the
    action layers declared by its canonical ActionContract and the chosen layer
    is exposed on the CapabilityItem for auditability.
    """

    model_config = ConfigDict(extra='forbid')

    contract_version: Literal['agom.v1'] = AGOM_CONTRACT_VERSION
    evaluation_policy_version: str
    entity: EntityRef
    projection: ProjectionSnapshot
    actor_role: str
    actor_responsibilities: list[str] = Field(default_factory=list)
    capabilities: list[CapabilityItem]
    generated_at: datetime


class DecisionPacket(BaseModel):
    model_config = ConfigDict(extra='forbid')

    contract_version: Literal['agom.v1'] = AGOM_CONTRACT_VERSION
    entity: EntityRef
    current_projection: ProjectionSnapshot
    requested_action: str
    risk_context: dict[str, Any] = Field(default_factory=dict)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    gate_results: list[GateResult] = Field(default_factory=list)
    sod_eligible: bool
    deadline: datetime | None = None
    downstream_effects: list[str] = Field(default_factory=list)
