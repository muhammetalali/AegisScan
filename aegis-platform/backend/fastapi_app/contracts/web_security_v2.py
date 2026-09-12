from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class GraphNodeIn(StrictModel):
    plane: Literal['application', 'identity', 'attack_surface', 'adversary', 'detection', 'risk', 'governance'] = 'application'
    kind: Literal[
        'page', 'endpoint', 'channel', 'graphql_operation', 'graphql_type',
        'graphql_field', 'graphql_argument', 'websocket_channel',
        'identity', 'session', 'role', 'tenant', 'resource', 'policy',
        'observation', 'evidence', 'finding', 'attack_chain', 'detection',
        'risk', 'control', 'remediation', 'revalidation', 'service', 'cache',
        'reverse_proxy', 'database', 'external_service', 'threat', 'ttp',
        'asset', 'capability', 'trust_boundary', 'data_flow',
    ]
    external_ref: str = Field(min_length=1, max_length=500)
    label: str = Field(min_length=1, max_length=300)
    protocol: str = Field(default='', max_length=32)
    tenant_ref: str = Field(default='', max_length=255)
    properties: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class GraphEdgeIn(StrictModel):
    source_ref: str = Field(min_length=1, max_length=500)
    target_ref: str = Field(min_length=1, max_length=500)
    relation: str = Field(min_length=1, max_length=80)
    evidence_refs: list[str] = Field(default_factory=list, max_length=1024)
    properties: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class GraphSnapshotIn(StrictModel):
    nodes: list[GraphNodeIn] = Field(min_length=1, max_length=10000)
    edges: list[GraphEdgeIn] = Field(default_factory=list, max_length=25000)


class AuthorizationPolicyIn(StrictModel):
    identity_type: str = Field(min_length=1, max_length=80)
    role: str = Field(default='*', max_length=120)
    tenant_ref: str = Field(default='*', max_length=255)
    endpoint: str = Field(min_length=1, max_length=700)
    session_ref: str = Field(default='', max_length=255)
    method: str = Field(default='*', min_length=1, max_length=16)
    operation: str = Field(default='*', max_length=160)
    resource_type: str = Field(default='*', max_length=160)
    allowed: bool
    ownership_rule: str = Field(default='', max_length=160)
    tenant_rule: str = Field(default='', max_length=160)
    sensitive_operation: bool = False
    required_scopes: list[str] = Field(default_factory=list, max_length=128)
    conditions: dict[str, Any] = Field(default_factory=dict)
    policy_source: Literal[
        'operator_declared', 'source_annotation', 'application_rbac',
        'oauth_scope', 'openapi_extension', 'observed_baseline',
    ]
    provenance: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    version: int = Field(default=1, ge=1, le=100000)


class ExecutionBudgetIn(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    environment: Literal['production', 'staging', 'development', 'digital_twin']
    allowed_capabilities: list[str] = Field(default_factory=list, max_length=256)
    max_requests: int = Field(default=1000, ge=0, le=10_000_000)
    network_io_bytes: int = Field(default=104857600, ge=0, le=1_000_000_000_000)
    browser_sessions: int = Field(default=2, ge=0, le=10000)
    identities: int = Field(default=5, ge=0, le=100000)
    object_mutations: int = Field(default=0, ge=0, le=10_000_000)
    parallelism: int = Field(default=4, ge=1, le=10000)
    cpu_seconds: int = Field(default=300, ge=0, le=10_000_000)
    memory_mb: int = Field(default=1024, ge=64, le=1_000_000)
    duration_seconds: int = Field(default=900, ge=1, le=31_536_000)
    state_changes: bool = False
    destructive_operations: bool = False
    state_change_policy: Literal['deny', 'conditional', 'allow'] = 'deny'
    version: int = Field(default=1, ge=1, le=100000)


class ExecutionRequestIn(StrictModel):
    capabilities: list[str] = Field(default_factory=list, max_length=256)
    requests: int = Field(default=0, ge=0)
    network_io_bytes: int = Field(default=0, ge=0)
    browser_sessions: int = Field(default=0, ge=0)
    identities: int = Field(default=0, ge=0)
    object_mutations: int = Field(default=0, ge=0)
    parallelism: int = Field(default=1, ge=1)
    cpu_seconds: int = Field(default=0, ge=0)
    memory_mb: int = Field(default=64, ge=0)
    duration_seconds: int = Field(default=0, ge=0)
    state_changes: bool = False
    destructive_operations: bool = False


class ProviderApprovalIn(StrictModel):
    provider_name: str = Field(min_length=1, max_length=180)
    provider_version: str = Field(min_length=1, max_length=120)
    status: Literal['approved', 'experimental', 'restricted', 'rejected']
    capability: str = Field(min_length=1, max_length=180)
    manifest: dict[str, Any]
    rationale: str = Field(default='', max_length=8000)


class ProviderGateCheckIn(StrictModel):
    approval_id: str = Field(min_length=1, max_length=64)
    requested_capability: str = Field(min_length=1, max_length=180)


class CapturedResponseIn(StrictModel):
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None
    timing_ms: float | None = Field(default=None, ge=0.0)


class IdentityIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=80)
    role: str = Field(default='', max_length=120)
    tenant_ref: str = Field(default='', max_length=255)
    scopes: list[str] = Field(default_factory=list, max_length=256)


class ResourceIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    type: str = Field(min_length=1, max_length=160)
    tenant_ref: str = Field(default='', max_length=255)
    owner_ref: str = Field(default='', max_length=255)


class AuthorizationCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    endpoint: str = Field(min_length=1, max_length=700)
    method: str = Field(min_length=1, max_length=16)
    operation: str = Field(default='', max_length=160)
    protocol: Literal['http', 'https', 'graphql', 'websocket', 'browser'] = 'https'
    session_ref: str = Field(default='', max_length=255)
    response: CapturedResponseIn


class AuthorizationMatrixIn(StrictModel):
    cases: list[AuthorizationCaseIn] = Field(min_length=1, max_length=5000)


class NegativeInvariantIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    type: Literal['deny_access', 'security_headers', 'cookie_flags', 'timing_consistency']
    response: CapturedResponseIn
    required_headers: list[str] = Field(default_factory=list, max_length=128)
    reference_timing_ms: float | None = Field(default=None, ge=0.0)
    tolerance_ms: float | None = Field(default=None, ge=0.0)


class NegativePathBatchIn(StrictModel):
    invariants: list[NegativeInvariantIn] = Field(min_length=1, max_length=5000)


class ResponseComparisonIn(StrictModel):
    baseline: CapturedResponseIn
    candidate: CapturedResponseIn


class WebSocketSecurityCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    channel: str = Field(min_length=1, max_length=700)
    session_ref: str = Field(default='', max_length=255)
    origin: str = Field(default='', max_length=700)
    allowed_origins: list[str] = Field(default_factory=list, max_length=128)
    authentication_required: bool = True
    authenticated: bool = False
    session_state: Literal['active', 'expired', 'revoked', 'unknown'] = 'unknown'
    requested_action: str = Field(default='subscribe', max_length=160)
    expected_allowed: bool
    server_accepted: bool
    handshake_status: int = Field(default=101, ge=100, le=599)
    subscription_owner_ref: str = Field(default='', max_length=255)
    subscription_tenant_ref: str = Field(default='', max_length=255)
    reconnect: bool = False
    reconnect_reauthenticated: bool = False
    message_schema_valid: bool = True
    message_authorized: bool = True
    binary: bool = False
    binary_allowed: bool = False
    message_size_bytes: int = Field(default=0, ge=0, le=100_000_000)
    max_message_size_bytes: int = Field(default=1_048_576, ge=1, le=100_000_000)
    observed_messages: int = Field(default=0, ge=0, le=10_000_000)
    rate_limit_threshold: int = Field(default=1000, ge=1, le=10_000_000)
    rate_limited: bool = False
    close_code: int | None = Field(default=None, ge=1000, le=4999)


class WebSocketSecurityBatchIn(StrictModel):
    budget_id: UUID
    cases: list[WebSocketSecurityCaseIn] = Field(min_length=1, max_length=5000)


class GraphQLSecurityCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    endpoint: str = Field(min_length=1, max_length=700)
    operation_type: Literal['query', 'mutation', 'subscription']
    operation_name: str = Field(min_length=1, max_length=160)
    document: str = Field(default='', max_length=262144)
    schema_sdl: str = Field(default='', max_length=1048576)
    schema_introspection: dict[str, Any] | None = None
    field_path: str = Field(default='', max_length=500)
    expected_allowed: bool
    server_accepted: bool
    response_status: int = Field(default=200, ge=100, le=599)
    errors_count: int = Field(default=0, ge=0, le=10000)
    field_authorized: bool = True
    mutation_authorized: bool = True
    subscription_owner_ref: str = Field(default='', max_length=255)
    subscription_tenant_ref: str = Field(default='', max_length=255)
    sensitive_fields_requested: list[str] = Field(default_factory=list, max_length=256)
    sensitive_fields_returned: list[str] = Field(default_factory=list, max_length=256)
    introspection_requested: bool = False
    introspection_expected_allowed: bool = False
    batch_size: int = Field(default=1, ge=1, le=10000)
    max_batch_size: int = Field(default=10, ge=1, le=10000)
    depth: int = Field(default=1, ge=1, le=1000)
    max_depth: int = Field(default=12, ge=1, le=1000)
    complexity: int = Field(default=1, ge=1, le=1_000_000)
    max_complexity: int = Field(default=1000, ge=1, le=1_000_000)


class GraphQLSecurityBatchIn(StrictModel):
    budget_id: UUID
    cases: list[GraphQLSecurityCaseIn] = Field(min_length=1, max_length=5000)


class CrossProtocolTransitionCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    session_ref: str = Field(min_length=1, max_length=255)
    from_protocol: Literal['browser', 'http', 'https', 'graphql', 'websocket']
    to_protocol: Literal['browser', 'http', 'https', 'graphql', 'websocket']
    operation: str = Field(min_length=1, max_length=160)
    expected_allowed: bool
    observed_allowed: bool
    identity_consistent: bool = True
    tenant_consistent: bool = True
    session_bound: bool = True
    source_observation_id: UUID
    target_observation_id: UUID


class CrossProtocolTransitionBatchIn(StrictModel):
    budget_id: UUID
    cases: list[CrossProtocolTransitionCaseIn] = Field(min_length=1, max_length=5000)
