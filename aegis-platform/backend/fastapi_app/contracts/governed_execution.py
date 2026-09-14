from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GovernedExecutionEnvelope(BaseModel):
    """Server-owned immutable execution contract persisted on the canonical Scan."""

    model_config = ConfigDict(extra='forbid', frozen=True)

    contract_version: Literal['1.0'] = '1.0'
    policy_version: str = Field(min_length=1, max_length=64)
    actor_ref: str = Field(min_length=1, max_length=255)
    tenant_scope_ref: str = Field(min_length=1, max_length=255)
    project_ref: str = Field(min_length=1, max_length=255)
    asset_ref: str = Field(min_length=1, max_length=255)
    authorization_ref: str = Field(min_length=1, max_length=255)
    requested_capability_id: str = Field(min_length=1, max_length=255)
    capability_id: str = Field(min_length=1, max_length=255)
    methodology_refs: list[str] = Field(default_factory=list)
    allowed_options: dict[str, Any] = Field(default_factory=dict)
    credential_bindings: list[str] = Field(default_factory=list)
    runner_profile: str = Field(min_length=1, max_length=64)
    execution_mode: str = Field(min_length=1, max_length=64)
    risk_class: str = Field(min_length=1, max_length=64)
    depth: Literal['quick', 'standard', 'deep', 'comprehensive']
    idempotency_key: str | None = Field(default=None, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    idempotency_fingerprint: str = Field(min_length=64, max_length=64)
    policy_fingerprint: str = Field(min_length=64, max_length=64)
