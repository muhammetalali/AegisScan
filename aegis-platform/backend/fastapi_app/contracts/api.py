from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ApiError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class UnifiedValidationOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["1.0"] = "1.0"
    id: str
    finding_id: str | None = None
    target_type: Literal["url", "ip", "api"]
    target_value: str
    profile: Literal["quick", "full", "custom"]
    engines: list[str]
    scope: str
    status: str
    progress: int = Field(ge=0, le=100)
    current_phase: str
    created_at: str
    audit_note: str


class AttackPathNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    kind: str
    criticality: str
    open_finding_weight: float = Field(ge=0)
    internet_exposed: bool = False


class AttackPathEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relationship: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackPathPath(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: list[str]
    risk_score: float = Field(ge=0, le=100)
    hops: int = Field(ge=0)


class AttackPathGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["1.0"] = "1.0"
    project_id: str
    source: Literal["postgresql"] = "postgresql"
    generated_at: datetime
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]


class ComplianceValidationItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    framework: str
    control: str
    status: Literal["pass", "fail", "partial", "not_assessed"]
    finding_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)


class ScenarioSimulationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["1.0"] = "1.0"
    scenario_id: str
    status: str
    deterministic: bool
    source: Literal["postgresql"] = "postgresql"
    pre_change_risk: float = Field(ge=0)
    post_change_risk: float = Field(ge=0)
    risk_reduction: float
    affected_nodes: list[str]
    recommendation: str
