import os
from datetime import timezone
from typing import List, Optional

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
import django

django.setup()

from asgiref.sync import sync_to_async
from django.db.models import Count, Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.dependencies import get_current_user
from compliance.models import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceReport,
)
from projects.models import Project

router = APIRouter()


class FrameworkResponse(BaseModel):
    id: str
    name: str
    framework_type: str
    version: str
    controls_count: int
    is_active: bool


class ControlResponse(BaseModel):
    id: str
    framework_id: str
    control_id: str
    title: str
    description: str
    priority: str
    category: str


class AssessmentResponse(BaseModel):
    id: str
    project_id: str
    framework_id: str
    control_id: str
    status: str
    evidence: str
    assessed_at: Optional[str] = None
    next_review: Optional[str] = None


class AssessmentUpdate(BaseModel):
    status: Optional[str] = None
    evidence: Optional[str] = None
    remediation_plan: Optional[str] = None
    remediation_deadline: Optional[str] = None
    notes: Optional[str] = None


def _framework_response(framework: ComplianceFramework) -> FrameworkResponse:
    return FrameworkResponse(
        id=str(framework.id),
        name=framework.name,
        framework_type=framework.framework_type,
        version=framework.version,
        controls_count=framework.controls_count or framework.controls.count(),
        is_active=framework.is_active,
    )


def _control_response(control: ComplianceControl) -> ControlResponse:
    return ControlResponse(
        id=str(control.id),
        framework_id=str(control.framework_id),
        control_id=control.control_id,
        title=control.title,
        description=control.description,
        priority=control.priority,
        category=control.category,
    )


def _assessment_response(assessment: ComplianceAssessment) -> AssessmentResponse:
    return AssessmentResponse(
        id=str(assessment.id),
        project_id=str(assessment.project_id),
        framework_id=str(assessment.framework_id),
        control_id=str(assessment.control_id),
        status=assessment.status,
        evidence=assessment.evidence,
        assessed_at=assessment.assessed_at.astimezone(timezone.utc).isoformat() if assessment.assessed_at else None,
        next_review=assessment.next_review.astimezone(timezone.utc).isoformat() if assessment.next_review else None,
    )


@sync_to_async
def _has_project_access(project_id: str, user_id: str) -> bool:
    return Project.objects.filter(id=project_id).filter(
        Q(owner_id=user_id) | Q(members__id=user_id)
    ).exists()


@sync_to_async
def _list_frameworks(active_only: bool):
    qs = ComplianceFramework.objects.all().prefetch_related("controls")
    if active_only:
        qs = qs.filter(is_active=True)
    return [_framework_response(x) for x in qs]


@router.get("/frameworks", response_model=List[FrameworkResponse])
async def list_frameworks(
    active_only: bool = True,
    user=Depends(get_current_user),
):
    return await _list_frameworks(active_only)


@sync_to_async
def _get_controls(framework_id: str):
    if not ComplianceFramework.objects.filter(id=framework_id).exists():
        raise HTTPException(status_code=404, detail="Framework not found")
    return [_control_response(x) for x in ComplianceControl.objects.filter(framework_id=framework_id)]


@router.get("/frameworks/{framework_id}/controls", response_model=List[ControlResponse])
async def get_framework_controls(framework_id: str, user=Depends(get_current_user)):
    return await _get_controls(framework_id)


@sync_to_async
def _list_assessments(project_id: str, user_id: str, framework_id: Optional[str], status: Optional[str]):
    if not Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).exists():
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")
    qs = ComplianceAssessment.objects.filter(project_id=project_id).select_related("framework", "control")
    if framework_id:
        qs = qs.filter(framework_id=framework_id)
    if status:
        qs = qs.filter(status=status)
    return [_assessment_response(x) for x in qs.order_by("framework_id", "control__control_id")]


@router.get("/projects/{project_id}/assessments", response_model=List[AssessmentResponse])
async def list_assessments(
    project_id: str,
    framework_id: Optional[str] = None,
    status: Optional[str] = None,
    user=Depends(get_current_user),
):
    return await _list_assessments(project_id, str(user.get("user_id")), framework_id, status)


@sync_to_async
def _update_assessment(assessment_id: str, user_id: str, update: AssessmentUpdate):
    assessment = ComplianceAssessment.objects.filter(id=assessment_id).filter(
        Q(project__owner_id=user_id) | Q(project__members__id=user_id)
    ).select_related("framework", "control").first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    data = update.model_dump(exclude_unset=True)
    for key, value in data.items():
        setattr(assessment, key, value)
    assessment.save(update_fields=[*data.keys(), "updated_at"])
    return _assessment_response(assessment)


@router.patch("/assessments/{assessment_id}", response_model=AssessmentResponse)
async def update_assessment(assessment_id: str, update: AssessmentUpdate, user=Depends(get_current_user)):
    return await _update_assessment(assessment_id, str(user.get("user_id")), update)


@sync_to_async
def _run_assessment(project_id: str, framework_id: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")
    framework = ComplianceFramework.objects.filter(id=framework_id, is_active=True).first()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    controls = ComplianceControl.objects.filter(framework=framework)
    created = 0
    for control in controls:
        _, was_created = ComplianceAssessment.objects.get_or_create(
            project=project,
            framework=framework,
            control=control,
            defaults={"assessed_by_id": user_id},
        )
        created += int(was_created)
    return {"framework_id": str(framework.id), "project_id": str(project.id), "controls_processed": controls.count(), "assessments_created": created}


@router.post("/projects/{project_id}/assess", response_model=dict)
async def run_compliance_assessment(project_id: str, framework_id: str, user=Depends(get_current_user)):
    return await _run_assessment(project_id, framework_id, str(user.get("user_id")))


@sync_to_async
def _generate_report(project_id: str, framework_id: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")
    framework = ComplianceFramework.objects.filter(id=framework_id).first()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    qs = ComplianceAssessment.objects.filter(project=project, framework=framework)
    counts = qs.aggregate(
        total=Count("id"),
        compliant=Count("id", filter=Q(status=ComplianceAssessment.Status.COMPLIANT)),
        non_compliant=Count("id", filter=Q(status=ComplianceAssessment.Status.NON_COMPLIANT)),
        partial=Count("id", filter=Q(status=ComplianceAssessment.Status.PARTIAL)),
        not_applicable=Count("id", filter=Q(status=ComplianceAssessment.Status.NOT_APPLICABLE)),
    )
    assessed = counts["compliant"] + counts["non_compliant"] + counts["partial"] + counts["not_applicable"]
    percentage = round(((counts["compliant"] + counts["partial"] * 0.5) / assessed) * 100, 2) if assessed else 0.0
    if counts["non_compliant"]:
        overall = ComplianceAssessment.Status.NON_COMPLIANT
    elif counts["partial"]:
        overall = ComplianceAssessment.Status.PARTIAL
    elif assessed and counts["compliant"] + counts["not_applicable"] == assessed:
        overall = ComplianceAssessment.Status.COMPLIANT
    else:
        overall = ComplianceAssessment.Status.NOT_ASSESSED
    report = ComplianceReport.objects.create(
        project=project,
        framework=framework,
        title=f"{framework.name} compliance report",
        overall_status=overall,
        total_controls=counts["total"],
        compliant_count=counts["compliant"],
        non_compliant_count=counts["non_compliant"],
        partial_count=counts["partial"],
        not_applicable_count=counts["not_applicable"],
        compliance_percentage=percentage,
        report_data={"generated_from": "database", "assessment_count": counts["total"]},
        generated_by_id=user_id,
    )
    return {"report_id": str(report.id), "compliance_percentage": percentage, "overall_status": overall}


@router.get("/projects/{project_id}/report")
async def generate_compliance_report(project_id: str, framework_id: str, user=Depends(get_current_user)):
    return await _generate_report(project_id, framework_id, str(user.get("user_id")))


@sync_to_async
def _dashboard(project_id: str, user_id: str):
    if not Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).exists():
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")
    qs = ComplianceAssessment.objects.filter(project_id=project_id)
    counts = qs.aggregate(
        compliant=Count("id", filter=Q(status=ComplianceAssessment.Status.COMPLIANT)),
        partial=Count("id", filter=Q(status=ComplianceAssessment.Status.PARTIAL)),
        non_compliant=Count("id", filter=Q(status=ComplianceAssessment.Status.NON_COMPLIANT)),
        not_applicable=Count("id", filter=Q(status=ComplianceAssessment.Status.NOT_APPLICABLE)),
        total=Count("id"),
    )
    assessed = counts["compliant"] + counts["partial"] + counts["non_compliant"] + counts["not_applicable"]
    score = round(((counts["compliant"] + counts["partial"] * 0.5) / assessed) * 100, 2) if assessed else 0.0
    return {
        "overall_compliance": score,
        "assessments": counts["total"],
        "by_status": {
            "compliant": counts["compliant"],
            "partial": counts["partial"],
            "non_compliant": counts["non_compliant"],
            "not_applicable": counts["not_applicable"],
        },
    }


@router.get("/projects/{project_id}/dashboard")
async def get_compliance_dashboard(project_id: str, user=Depends(get_current_user)):
    return await _dashboard(project_id, str(user.get("user_id")))
