
from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from fastapi_app.contracts.web_security_v2 import IdentityIn, ResourceIn


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


CacheDimension = Literal[
    'scheme', 'host', 'path', 'query', 'authorization', 'cookie', 'tenant', 'identity'
]


class CacheObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    shared: bool
    cache_hit: bool
    authenticated_response: bool = False
    response_private: bool = False
    response_no_store: bool = False
    required_key_dimensions: list[CacheDimension] = Field(default_factory=list, max_length=16)
    observed_key_dimensions: list[CacheDimension] = Field(default_factory=list, max_length=16)
    cache_key_sha256: str = Field(default='', max_length=64)
    partition_sha256: str = Field(default='', max_length=64)


class ProxyTrustObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    source_trusted: bool
    forwarded_headers_present: bool = False
    forwarded_headers_accepted: bool = False
    forwarded_chain_valid: bool = True
    host_selected_from_forwarded: bool = False
    scheme_selected_from_forwarded: bool = False
    client_identity_selected_from_forwarded: bool = False


class OriginObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    expected_origin_ref: str = Field(min_length=1, max_length=255)
    selected_origin_ref: str = Field(min_length=1, max_length=255)
    authority_matches_request: bool = True
    host_override_present: bool = False
    host_override_trusted: bool = False
    host_override_accepted: bool = False


class DNSObservationIn(StrictModel):
    resolver_ref: str = Field(min_length=1, max_length=255)
    resolver_trusted: bool = True
    query_name_sha256: str = Field(min_length=64, max_length=64)
    answer_set_sha256: str = Field(min_length=64, max_length=64)
    connected_address_sha256: str = Field(min_length=64, max_length=64)
    connected_address_in_answer_set: bool = True
    answer_changed_within_request: bool = False
    revalidation_performed: bool = True
    binding_verified: bool = True
    private_address_observed: bool = False
    private_address_allowed: bool = False
    ttl_seconds: int | None = Field(default=None, ge=0, le=604800)


class CacheOriginCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    endpoint: str = Field(min_length=1, max_length=700)
    method: str = Field(min_length=1, max_length=32)
    operation: str = Field(default='request', max_length=160)
    expected_allowed: bool
    server_accepted: bool
    caches: list[CacheObservationIn] = Field(default_factory=list, max_length=8)
    proxy_hops: list[ProxyTrustObservationIn] = Field(default_factory=list, max_length=8)
    origin: OriginObservationIn
    dns: list[DNSObservationIn] = Field(default_factory=list, max_length=8)


class CacheOriginBatchIn(StrictModel):
    budget_id: UUID
    target_origin: str = Field(min_length=1, max_length=700)
    cases: list[CacheOriginCaseIn] = Field(min_length=1, max_length=5000)
