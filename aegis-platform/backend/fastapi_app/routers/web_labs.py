from __future__ import annotations

from typing import Literal
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..core.dependencies import get_current_user
from ..services.web_labs_preparation import UnknownLabDefinition, WebLabsAccessError, prepare_web_lab


class ArabicValidationRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                # Do not echo rejected input: it may contain a pasted credential.
                return JSONResponse(status_code=422, content={'detail': {
                    'code': 'invalid_preparation_input',
                    'message_ar': 'مدخلات التجهيز غير صالحة؛ استخدم المراجع والحقول المعتمدة فقط.',
                    'errors': [{'field': '.'.join(map(str, e['loc'])), 'code': e['type']}
                               for e in exc.errors()],
                }})
        return handler


router = APIRouter(route_class=ArabicValidationRoute)


class PrepareWebLabIn(BaseModel):
    model_config = ConfigDict(extra='forbid')
    project_id: UUID
    asset_id: UUID
    lab_definition_id: str = Field(min_length=1, max_length=80, pattern=r'^[a-z0-9][a-z0-9-]*$')
    credential_refs: list[UUID] = Field(default_factory=list, max_length=3)
    depth: Literal['quick', 'standard', 'deep', 'comprehensive'] = 'standard'

    @field_validator('credential_refs')
    @classmethod
    def unique_refs(cls, refs):
        if len(refs) != len(set(refs)):
            raise ValueError('duplicate_credential_refs')
        return refs


class ContractModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Requirement(ContractModel):
    id: str
    state: Literal['ready', 'blocked', 'unverified']
    observed_state: str
    message_ar: str
    suggested_action_ar: str


class Blocker(ContractModel):
    code: str
    requirement_ref: str
    observed_state: str
    message_ar: str
    suggested_action_ar: str


class ProviderMetadata(ContractModel):
    state: str
    decision_ref: str | None


class CredentialMetadata(ContractModel):
    credential_ref: str
    identity_ref: str | None
    state: str
    version: int | None
    message_ar: str


class CapabilityMetadata(ContractModel):
    id: str
    registered: bool
    runtime_verified: Literal[False]


class PrepareWebLabOut(ContractModel):
    contract_version: Literal['aegis.web-labs-readiness.v1']
    project_ref: str
    asset_ref: str
    lab_ref: str
    fixture_revision: str
    methodology_refs: list[str]
    depth: str
    preview_only: Literal[True]
    execution_ready: bool
    metadata_ready: bool
    authorization_ref: str | None
    provider: ProviderMetadata
    credential_metadata: list[CredentialMetadata]
    supported_operations: list[str]
    capabilities: list[CapabilityMetadata]
    requirements: list[Requirement]
    blockers: list[Blocker]
    explanation_ar: str


@router.post('/prepare', response_model=PrepareWebLabOut)
async def prepare(payload: PrepareWebLabIn, user=Depends(get_current_user)):
    actor_id = user.get('user_id') or user.get('id')
    if not actor_id:
        raise HTTPException(401, detail={'code': 'invalid_actor', 'message_ar': 'هوية المستخدم غير متاحة.'})
    try:
        return await sync_to_async(prepare_web_lab, thread_sensitive=True)(
            actor_id=str(actor_id), project_id=str(payload.project_id), asset_id=str(payload.asset_id),
            lab_definition_id=payload.lab_definition_id,
            credential_refs=[str(ref) for ref in payload.credential_refs], depth=payload.depth,
        )
    except WebLabsAccessError as exc:
        raise HTTPException(404, detail={'code': 'unavailable_scope', 'message_ar': str(exc)}) from exc
    except UnknownLabDefinition as exc:
        raise HTTPException(422, detail={'code': 'unknown_lab_definition', 'message_ar': str(exc)}) from exc
