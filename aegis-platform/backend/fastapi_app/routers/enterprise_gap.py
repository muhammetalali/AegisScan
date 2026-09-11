from __future__ import annotations

from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.services.enterprise_gap_closure import (
    append_finding_decision,
    create_investigation_case,
    enrich_finding_priority,
    persist_blast_radius,
    persist_evidence_graph,
    predict_novel_exposure,
    record_artifact_integrity,
    update_feedback_weights,
    verify_finding_decision_chain,
    verify_policy_constraints,
)

router=APIRouter()


class StrictModel(BaseModel):
    model_config=ConfigDict(extra='forbid')


class DecisionIn(StrictModel):
    decision:str=Field(min_length=1,max_length=80)
    policy_ref:str=Field(min_length=1,max_length=240)
    reason:str=Field(min_length=1,max_length=4000)
    evidence_refs:list[str]=Field(default_factory=list,max_length=128)
    new_status:str|None=None
    validation_id:str|None=None


class CaseIn(StrictModel):
    title:str=Field(min_length=1,max_length=240)
    description:str=Field(default='',max_length=8000)
    finding_ids:list[str]=Field(default_factory=list,max_length=256)
    evidence_ids:list[str]=Field(default_factory=list,max_length=256)


class WeightUpdateIn(StrictModel):
    features:dict[str,float]
    reward:float=Field(ge=-1,le=1)
    learning_rate:float=Field(default=0.08,gt=0,le=0.5)


class ExposureIn(StrictModel):
    features:dict[str,float]


class ProofIn(StrictModel):
    proof_type:str=Field(min_length=1,max_length=80)
    facts:dict[str,bool]


class GraphIn(StrictModel):
    nodes:list[dict[str,Any]]=Field(max_length=5000)
    edges:list[dict[str,Any]]=Field(max_length=10000)


class BlastIn(StrictModel):
    root_ref:str=Field(min_length=1,max_length=255)
    impacted_nodes:list[dict[str,Any]]=Field(max_length=5000)
    crown_jewel_refs:list[str]=Field(default_factory=list,max_length=1000)
    evidence_refs:list[str]=Field(default_factory=list,max_length=5000)
    attack_path_id:str|None=None


class ArtifactIn(StrictModel):
    artifact_type:str=Field(min_length=1,max_length=40)
    name:str=Field(min_length=1,max_length=300)
    source_ref:str=Field(min_length=1,max_length=700)
    sha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    signature_verified:bool=False
    provenance_verified:bool=False
    package_namespace:str=Field(default='',max_length=300)
    trusted_namespaces:list[str]=Field(default_factory=list,max_length=256)
    metadata:dict[str,Any]=Field(default_factory=dict)


@sync_to_async
def _project_for_user(project_id:str,user_id:str):
    return (
        Project.objects.filter(pk=project_id,owner_id=user_id).first()
        or Project.objects.filter(pk=project_id,members__id=user_id).first()
    )


@sync_to_async
def _finding_for_user(finding_id:str,user_id:str):
    return (
        Vulnerability.objects.filter(pk=finding_id,project__owner_id=user_id).first()
        or Vulnerability.objects.filter(pk=finding_id,project__members__id=user_id).first()
    )


def _uid(user:dict)->str:
    value=user.get('user_id') or user.get('sub')
    if not value:
        raise HTTPException(status_code=401,detail='Invalid authenticated user')
    return str(value)


@router.post('/findings/{finding_id}/decisions',status_code=201)
async def record_decision(finding_id:UUID,payload:DecisionIn,user=Depends(get_current_user)):
    uid=_uid(user)
    finding=await _finding_for_user(str(finding_id),uid)
    if finding is None: raise HTTPException(status_code=404,detail='Finding not found')
    try:
        row=await sync_to_async(append_finding_decision)(
            vulnerability_id=str(finding_id),actor_id=uid,**payload.model_dump()
        )
    except (ValueError,PermissionError) as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    return {'id':str(row.id),'entry_hash':row.entry_hash,'previous_hash':row.previous_hash,'decision':row.decision,'new_status':row.new_status}


@router.get('/findings/{finding_id}/decisions/verify')
async def verify_decisions(finding_id:UUID,user=Depends(get_current_user)):
    uid=_uid(user)
    finding=await _finding_for_user(str(finding_id),uid)
    if finding is None: raise HTTPException(status_code=404,detail='Finding not found')
    return await sync_to_async(verify_finding_decision_chain)(str(finding_id))


@router.post('/findings/{finding_id}/priority')
async def enrich_priority(finding_id:UUID,user=Depends(get_current_user)):
    uid=_uid(user)
    finding=await _finding_for_user(str(finding_id),uid)
    if finding is None: raise HTTPException(status_code=404,detail='Finding not found')
    try:
        return await sync_to_async(enrich_finding_priority)(str(finding_id))
    except (ValueError,PermissionError) as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post('/projects/{project_id}/cases',status_code=201)
async def new_case(project_id:UUID,payload:CaseIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    try:
        case=await sync_to_async(create_investigation_case)(project=project,owner_id=uid,**payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    return {'id':str(case.id),'status':case.status,'title':case.title}


@router.post('/projects/{project_id}/adaptive-weights')
async def learn_weights(project_id:UUID,payload:WeightUpdateIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    row=await sync_to_async(update_feedback_weights)(project=project,**payload.model_dump())
    return {'version':row.version,'weights':row.weights,'learned_from':row.learned_from,'reward_mean':row.reward_mean,'algorithm':row.algorithm}


@router.post('/projects/{project_id}/predictive-exposure')
async def predictive_exposure(project_id:UUID,payload:ExposureIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    return predict_novel_exposure(payload.features)


@router.post('/projects/{project_id}/formal-policy-proof',status_code=201)
async def formal_proof(project_id:UUID,payload:ProofIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    proof=await sync_to_async(verify_policy_constraints)(project=project,proof_type=payload.proof_type,facts=payload.facts)
    return {'proof_id':str(proof.id),'satisfiable':proof.satisfiable,'model':proof.model,'solver':proof.solver,'solver_version':proof.solver_version}


@router.put('/projects/{project_id}/evidence-graph')
async def evidence_graph(project_id:UUID,payload:GraphIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    try:
        return await sync_to_async(persist_evidence_graph)(project=project,nodes=payload.nodes,edges=payload.edges)
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc


@router.post('/projects/{project_id}/blast-radius',status_code=201)
async def blast_radius(project_id:UUID,payload:BlastIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    row=await sync_to_async(persist_blast_radius)(project=project,**payload.model_dump())
    return {'id':str(row.id),'root_ref':row.root_ref,'score':row.score,'crown_jewel_refs':row.crown_jewel_refs}


@router.post('/projects/{project_id}/artifact-integrity',status_code=201)
async def artifact_integrity(project_id:UUID,payload:ArtifactIn,user=Depends(get_current_user)):
    uid=_uid(user); project=await _project_for_user(str(project_id),uid)
    if project is None: raise HTTPException(status_code=404,detail='Project not found')
    values=payload.model_dump()
    trusted=values.pop('trusted_namespaces')
    row=await sync_to_async(record_artifact_integrity)(project=project,user_id=uid,trusted_namespaces=trusted,**values)
    return {'id':str(row.id),'state':row.state,'quarantine_reason':row.quarantine_reason,'sha256':row.sha256}
