from __future__ import annotations

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
import django

django.setup()

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from ..contracts import ComplianceValidationItem
from ..core.dependencies import get_current_user
from compliance.models import ComplianceAssessment
from evidence.models import ValidationRun
from projects.models import Project

router = APIRouter()


def _status(value: str) -> str:
    mapping = {
        ComplianceAssessment.Status.COMPLIANT: "pass",
        ComplianceAssessment.Status.NON_COMPLIANT: "fail",
        ComplianceAssessment.Status.PARTIAL: "partial",
        ComplianceAssessment.Status.NOT_APPLICABLE: "not_assessed",
        ComplianceAssessment.Status.NOT_ASSESSED: "not_assessed",
    }
    return mapping.get(value, "not_assessed")


@sync_to_async
def _get_items(validation_id: str, user_id: str) -> list[ComplianceValidationItem]:
    validation = ValidationRun.objects.select_related("finding__project").filter(id=validation_id, user_id=user_id).first()
    if not validation or not validation.finding_id:
        raise HTTPException(status_code=404, detail="Validation not found or has no finding")

    project = validation.finding.project
    if not Project.objects.filter(id=project.id).filter(owner_id=user_id).exists() and not project.members.filter(pk=user_id).exists():
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")

    assessments = ComplianceAssessment.objects.filter(project_id=project.id).select_related("framework", "control").prefetch_related("findings")
    return [
        ComplianceValidationItem(
            id=str(assessment.id),
            framework=str(assessment.framework.name),
            control=str(assessment.control.title or assessment.control.control_id),
            status=_status(str(assessment.status)),
            finding_count=assessment.findings.count(),
            evidence_count=1 if assessment.evidence.strip() else 0,
        )
        for assessment in assessments.order_by("framework__name", "control__control_id")
    ]


@router.get("/validations/{validation_id}/compliance", response_model=list[ComplianceValidationItem])
async def validation_compliance(validation_id: str, user=Depends(get_current_user)):
    return await _get_items(validation_id, str(user.get("user_id")))
