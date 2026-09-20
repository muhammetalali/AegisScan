from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .governed_operations import GateResult, ProjectionSnapshot


class GovernedActionExecuteRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    action_id: str = Field(min_length=1, max_length=128)
    project_id: str = Field(min_length=1)
    entity_type: str = Field(min_length=1, max_length=80)
    entity_id: str = Field(min_length=1, max_length=128)
    expected_version: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=128)
    request_id: UUID | None = None
    correlation_id: UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class GovernedActionAuditView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    audit_id: str
    chain_index: int
    entry_hash: str


class GovernedActionExecutionView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    execution_id: str
    action_id: str
    organization_id: str
    project_id: str
    actor_id: str
    request_id: str | None = None
    entity_type: str
    entity_id: str
    expected_version: int
    idempotency_key: str
    request_fingerprint: str
    contract_version: str
    contract_policy_version: str
    evaluation_policy_version: str
    policy_fingerprint: str
    correlation_id: UUID
    before_projection: ProjectionSnapshot
    gate_results: list[GateResult] = Field(default_factory=list)
    result: dict[str, Any] = Field(default_factory=dict)
    after_projection: ProjectionSnapshot
    audit: GovernedActionAuditView
    execution_fingerprint: str
    replayed: bool
    created_at: datetime

class GovernedActionRequestCreate(BaseModel):
    model_config = ConfigDict(extra='forbid')

    action_id: str = Field(min_length=1, max_length=128)
    project_id: str = Field(min_length=1)
    entity_type: str = Field(min_length=1, max_length=80)
    entity_id: str = Field(min_length=1, max_length=128)
    expected_version: int = Field(ge=1)
    idempotency_key: str = Field(min_length=1, max_length=128)
    correlation_id: UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class GovernedActionRequestView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    request_id: str
    organization_id: str
    project_id: str
    requested_by_id: str
    action_id: str
    entity_type: str
    entity_id: str
    expected_version: int
    idempotency_key: str
    request_fingerprint: str
    contract_version: str
    contract_policy_version: str
    contract_fingerprint: str
    correlation_id: UUID
    parameters: dict[str, Any] = Field(default_factory=dict)
    replayed: bool
    created_at: datetime
