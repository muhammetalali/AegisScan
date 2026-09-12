from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from fastapi_app.contracts.web_security_v2 import IdentityIn, ResourceIn


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class HttpHopObservationIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    role: Literal['client', 'edge', 'gateway', 'origin']
    protocol: Literal['http/1.0', 'http/1.1', 'h2', 'h3']
    method: str = Field(min_length=1, max_length=32)
    path: str = Field(min_length=1, max_length=1500)
    authority: str = Field(default='', max_length=700)
    host: str = Field(default='', max_length=700)
    content_length_values: list[int] = Field(default_factory=list, max_length=16)
    body_length_bytes: int | None = Field(default=None, ge=0)
    semantic_body_sha256: str = Field(default='', max_length=64)
    transfer_encodings: list[str] = Field(default_factory=list, max_length=16)
    te_header_values: list[str] = Field(default_factory=list, max_length=16)
    connection_tokens: list[str] = Field(default_factory=list, max_length=64)
    pseudo_headers_valid: bool = True
    pseudo_headers_order_valid: bool = True
    message_complete: bool = True
    parser_accepted: bool = True
    framing_boundary_ref: str = Field(default='', max_length=255)
    trailer_declared: list[str] = Field(default_factory=list, max_length=64)
    trailer_observed: list[str] = Field(default_factory=list, max_length=64)


class HttpResponseObservationIn(StrictModel):
    protocol: Literal['http/1.0', 'http/1.1', 'h2', 'h3']
    status_code: int = Field(ge=100, le=599)
    content_length_values: list[int] = Field(default_factory=list, max_length=16)
    body_length_bytes: int | None = Field(default=None, ge=0)
    connection_tokens: list[str] = Field(default_factory=list, max_length=64)
    transfer_encodings: list[str] = Field(default_factory=list, max_length=16)
    te_header_values: list[str] = Field(default_factory=list, max_length=16)
    trailer_declared: list[str] = Field(default_factory=list, max_length=64)
    trailer_observed: list[str] = Field(default_factory=list, max_length=64)


class HttpProtocolCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    identity: IdentityIn
    resource: ResourceIn
    endpoint: str = Field(min_length=1, max_length=700)
    method: str = Field(min_length=1, max_length=32)
    operation: str = Field(default='request', max_length=160)
    expected_allowed: bool
    server_accepted: bool
    hops: list[HttpHopObservationIn] = Field(min_length=1, max_length=8)
    response: HttpResponseObservationIn | None = None


class HttpProtocolBatchIn(StrictModel):
    budget_id: UUID
    target_origin: str = Field(min_length=1, max_length=700)
    cases: list[HttpProtocolCaseIn] = Field(min_length=1, max_length=5000)
