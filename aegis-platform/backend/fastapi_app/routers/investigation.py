from __future__ import annotations
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE','django_project.settings')
import django
django.setup()
from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from ..core.dependencies import get_current_user
from django_project.audit.models import AuditLog
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import AttackPath, FindingIntelligence
router=APIRouter()
class InvestigationFinding(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str; title:str; severity:str; status:str; risk_score:float; asset_id:str|None=None; asset_name:str|None=None; source_engine:str
class InvestigationEvidence(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str; finding_id:str|None=None; scan_id:str|None=None; source:str; evidence_type:str; sha256:str; collected_at:str
class InvestigationAttackPath(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str; source_node:dict; target_node:dict; steps:list; risk_score:float; status:str
class InvestigationIntel(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str; finding_id:str; cve_id:str; analysis_version:str; confidence:float; recommendation:str; explanation:str; snapshot_sha256:str; observed_at:str
class InvestigationWorkspace(BaseModel):
    model_config=ConfigDict(extra='forbid')
    contract_version:str='1.0'; source:str='postgresql'; project_id:str; findings:list[InvestigationFinding]; evidence:list[InvestigationEvidence]; attack_paths:list[InvestigationAttackPath]; intelligence:list[InvestigationIntel]; audit_events:int
@sync_to_async
def _workspace(project_id:str,user_id:str,finding_id:str|None,limit:int)->InvestigationWorkspace:
    project=Project.objects.filter(id=project_id).filter(Q(owner_id=user_id)|Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404,detail='Project not found or inaccessible')
    qs=Vulnerability.objects.filter(project=project).select_related('asset').order_by('-risk_score','-updated_at')
    if finding_id: qs=qs.filter(id=finding_id)
    findings=list(qs[:limit]); ids={str(x.id) for x in findings}
    evidence_qs=Evidence.objects.filter(Q(finding_id__in=ids)|Q(scan__project_id=project_id)|Q(asset__project_id=project_id)).distinct().order_by('-collected_at')[:limit]
    paths=AttackPath.objects.filter(project_id=project_id).order_by('-risk_score','-discovered_at')[:limit]
    intel=FindingIntelligence.objects.filter(vulnerability_id__in=ids,source_snapshot__isnull=False).select_related('source_snapshot').order_by('-calculated_at')[:limit]
    return InvestigationWorkspace(
        project_id=str(project.id),
        findings=[InvestigationFinding(id=str(x.id),title=x.title,severity=x.severity,status=x.status,risk_score=float(x.risk_score),asset_id=str(x.asset_id) if x.asset_id else None,asset_name=x.asset.name if x.asset_id and x.asset else None,source_engine=x.source_engine or 'unknown') for x in findings],
        evidence=[InvestigationEvidence(id=str(x.id),finding_id=str(x.finding_id) if x.finding_id else None,scan_id=str(x.scan_id) if x.scan_id else None,source=x.source,evidence_type=x.evidence_type,sha256=x.sha256,collected_at=x.collected_at.isoformat()) for x in evidence_qs],
        attack_paths=[InvestigationAttackPath(id=str(x.id),source_node=x.source_node,target_node=x.target_node,steps=x.steps,risk_score=float(x.risk_score),status=x.status) for x in paths],
        intelligence=[InvestigationIntel(id=str(x.source_snapshot_id),finding_id=str(x.vulnerability_id),cve_id=x.primary_cve,analysis_version=x.analysis_version,confidence=float(x.confidence),recommendation=x.recommendation,explanation=x.explanation,snapshot_sha256=x.source_snapshot.snapshot_sha256,observed_at=x.source_snapshot.observed_at.isoformat()) for x in intel],
        audit_events=AuditLog.objects.filter(Q(resource_type='project',resource_id=str(project.id))|Q(resource_type='finding',resource_id__in=ids)).count(),
    )
@router.get('/projects/{project_id}',response_model=InvestigationWorkspace)
async def investigation_workspace(project_id:str,finding_id:str|None=Query(default=None),limit:int=Query(default=50,ge=1,le=200),user=Depends(get_current_user)):
    return await _workspace(project_id,str(user.get('user_id')),finding_id,limit)
