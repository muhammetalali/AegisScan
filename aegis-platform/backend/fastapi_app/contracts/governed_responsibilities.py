from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ResponsibilityGrantRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    organization_id: str = Field(min_length=1)
    membership_id: str = Field(min_length=1)
    responsibility: str = Field(min_length=1, max_length=64)
    scope_kind: str = Field(min_length=1, max_length=24)
    reason: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1, max_length=128)
    project_id: str | None = None
    entity_type: str = Field(default='', max_length=80)
    entity_id: str = Field(default='', max_length=128)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    supersedes_assignment_id: str | None = None


class ResponsibilityRevokeRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    reason: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1, max_length=128)


class ResponsibilityAssignmentView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    assignment_id: str
    organization_id: str
    project_id: str | None
    membership_id: str
    responsibility: str
    scope_kind: str
    entity_type: str
    entity_id: str
    valid_from: datetime
    valid_until: datetime | None
    policy_version: str
    request_fingerprint: str
    grant_fingerprint: str
    issued_by: str
    issued_at: datetime
    supersedes_assignment_id: str | None
    replayed: bool = False


class ResponsibilityRevocationView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    revocation_id: str
    assignment_id: str
    policy_version: str
    request_fingerprint: str
    revocation_fingerprint: str
    revoked_by: str
    revoked_at: datetime
    replayed: bool = False


class ActorAuthorityView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    organization_id: str
    project_id: str | None
    membership_id: str
    role: str
    responsibilities: list[str]


class ResponsibilityChainView(BaseModel):
    model_config = ConfigDict(extra='forbid')

    valid: bool
    entries: int = Field(ge=0)
    head: str = ''
    broken_at: int | None = None
    reason: str = ''
