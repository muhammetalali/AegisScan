from __future__ import annotations

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
import django

django.setup()

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from ..contracts import ComplianceValidationItem
from ..core.dependencies import get_current_user
from evidence.models import ValidationRun
from projects.models import Project
from compliance.models import ComplianceAssessment

router = APIRouter()


@sync_to_async
def _get_items(validation_id: str, user_id: str) -> list[ComplianceValidationItem]:
    validation = (
        ValidationRun.objects.select_related("finding__project")
        .filter(id=validation_id, user_id=user_id)
        .first()
    )
    if not validation or not validation.finding_id:
        raise HTTPException(status_code=404, detail="Validation not found or has no finding")

    project = validation.finding.project
    if not Project.objects.filter(id=project.id).filter(owner_id=user_id).exists() and not project.members.filter(pk=user_id).exists():
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")

    assessments = ComplianceAssessment.objects.filter(project_id=project.id).select_related("control__framework").order_by("control__framework__name", "control__code")
    items: list[ComplianceValidationItem] = []
    for assessment in assessments:
        status = str(getattr(assessment, "status", "not_assessed") or "not_assessed").lower()
        if status not in {"pass", "fail", "partial", "not_assessed"}:
            status = "not_assessed"
        finding_count = getattr(assessment, "finding_count", None)
        evidence_count = getattr(assessment, "evidence_count", None)
        items.append(
            ComplianceValidationItem(
                id=str(assessment.id),
                framework=str(assessment.control.framework.name),
                control=str(getattr(assessment.control, "name", None) or getattr(assessment.control, "code", assessment.control_id)),
                status=status,
                finding_count=max(0, int(finding_count or 0)),
                evidence_count=max(0, int(evidence_count or 0)),
            )
        )
    return items


@router.get("/validations/{validation_id}/compliance", response_model=list[ComplianceValidationItem])
async def validation_compliance(validation_id: str, user=Depends(get_current_user)):
    return await _get_items(validation_id, str(user.get("user_id")))
