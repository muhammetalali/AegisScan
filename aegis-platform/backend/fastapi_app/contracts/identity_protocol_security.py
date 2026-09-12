from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from fastapi_app.contracts.web_security_v2 import IdentityIn, ResourceIn


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class IdentityProtocolCaseIn(StrictModel):
    ref: str = Field(min_length=1, max_length=255)
    protocol: Literal['jwt', 'oauth2', 'oidc', 'saml', 'session']
    identity: IdentityIn
    resource: ResourceIn
    endpoint: str = Field(min_length=1, max_length=700)
    operation: str = Field(default='authenticate', max_length=160)
    session_ref: str = Field(default='', max_length=255)
    expected_allowed: bool
    server_accepted: bool

    # JWT / OIDC token validation observations. Raw tokens are intentionally excluded.
    token_algorithm: str = Field(default='', max_length=32)
    allowed_algorithms: list[str] = Field(default_factory=list, max_length=32)
    signature_valid: bool = True
    issuer: str = Field(default='', max_length=700)
    expected_issuer: str = Field(default='', max_length=700)
    audiences: list[str] = Field(default_factory=list, max_length=128)
    expected_audiences: list[str] = Field(default_factory=list, max_length=128)
    token_expired: bool = False
    token_not_yet_valid: bool = False
    kid: str = Field(default='', max_length=255)
    kid_resolved: bool = True
    signing_key_status: Literal['active', 'retired', 'revoked', 'unknown'] = 'unknown'
    token_binding_required: bool = False
    token_binding_present: bool = False
    replay_detected: bool = False
    replay_rejected: bool = True

    # OAuth2 / OIDC authorization-code flow observations.
    redirect_uri: str = Field(default='', max_length=1000)
    registered_redirect_uris: list[str] = Field(default_factory=list, max_length=128)
    state_required: bool = True
    state_verified: bool = True
    nonce_required: bool = False
    nonce_verified: bool = True
    pkce_required: bool = True
    pkce_verified: bool = True
    pkce_method: Literal['S256', 'plain', 'none'] = 'S256'
    authorization_code_reused: bool = False
    authorization_code_reuse_rejected: bool = True

    # SAML observations. Raw assertions are intentionally excluded.
    saml_response_signature_valid: bool = True
    saml_assertion_signature_valid: bool = True
    saml_signature_required: bool = True
    saml_expected_audience: str = Field(default='', max_length=700)
    saml_observed_audience: str = Field(default='', max_length=700)
    saml_expected_recipient: str = Field(default='', max_length=1000)
    saml_observed_recipient: str = Field(default='', max_length=1000)
    saml_destination_valid: bool = True
    saml_in_response_to_valid: bool = True
    saml_conditions_valid: bool = True
    saml_subject_confirmation_valid: bool = True
    saml_signature_wrapping_rejected: bool = True

    # Session security observations.
    session_state: Literal['active', 'expired', 'revoked', 'unknown'] = 'unknown'
    session_rotated_after_auth: bool = True
    session_rotated_after_privilege_change: bool = True
    session_fixation_detected: bool = False
    cookie_secure: bool = True
    cookie_http_only: bool = True
    cookie_same_site: Literal['Strict', 'Lax', 'None', 'Unknown'] = 'Lax'
    csrf_binding_required: bool = False
    csrf_binding_verified: bool = True


class IdentityProtocolBatchIn(StrictModel):
    budget_id: UUID
    target_origin: str = Field(min_length=1, max_length=700)
    cases: list[IdentityProtocolCaseIn] = Field(min_length=1, max_length=5000)
