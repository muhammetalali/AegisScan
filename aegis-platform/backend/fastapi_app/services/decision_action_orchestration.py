from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import uuid4

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from enterprise.models import (
    DecisionAction,
    DecisionActionEvent,
    Organization,
    OrganizationMembership,
    RiskCorrelationSnapshot,
    TenantProject,
)
from django_project.evidence.models import ValidationRun
from django_project.projects.models import Project

STATES = ["pending", "approved", "assigned", "in_progress", "awaiting_revalidation", "verified", "rejected", "deferred"]
TRANSITIONS: dict[str, set[str]] = {
    "pending": {"approved", "rejected", "deferred"}, "approved": {"assigned", "deferred"},
    "assigned": {"in_progress", "deferred"}, "in_progress": {"awaiting_revalidation", "deferred"},
    "awaiting_revalidation": {"verified", "in_progress", "deferred"},
    "verified": set(), "rejected": set(), "deferred": {"pending", "approved"},
}
_schema_ready = False


def initialize_action_store() -> None:
    global _schema_ready
    _schema_ready = True


def _ensure_schema() -> None:
    initialize_action_store()


def _hydrate(action: DecisionAction) -> dict[str, Any]:
    events = [
        {"type": event.event_type, "at": event.created_at.isoformat(), "actor": event.actor, "note": event.note}
        for event in action.events.all()
    ]
    risk_correlation = action.risk_correlation if action.risk_correlation_id else None
    return {
        "actionId": action.action_id,
        "decisionId": action.decision_id,
        "nodeId": action.node_id,
        "title": action.title,
        "owner": action.owner,
        "requestedBy": action.requested_by,
        "slaHours": action.sla_hours,
        "state": action.state,
        "riskBefore": action.risk_before,
        "confidenceBefore": action.confidence_before,
        "priority": action.priority,
        "recommendedAction": action.recommended_action,
        "remediationPlan": action.remediation_plan,
        "createdAt": action.created_at.isoformat(),
        "updatedAt": action.updated_at.isoformat(),
        "dueAt": (action.created_at + timedelta(hours=action.sla_hours)).isoformat(),
        "version": action.version,
        "slaStatus": action.sla_status,
        "escalationLevel": action.escalation_level,
        "events": events,
        "organizationId": str(action.organization_id),
        "projectId": str(action.project_id),
        "validationId": str(action.validation_id),
        "riskCorrelationId": str(action.risk_correlation_id) if action.risk_correlation_id else None,
        "riskCorrelationSha256": risk_correlation.correlation_sha256 if risk_correlation else None,
        "riskAnalysisVersion": risk_correlation.analysis_version if risk_correlation else None,
        "riskCorrelationPriority": risk_correlation.priority if risk_correlation else None,
        "riskCorrelationScore": float(risk_correlation.score) if risk_correlation else None,
    }


def _validation_project_id(validation: ValidationRun) -> str | None:
    if validation.finding_id:
        return str(validation.finding.project_id)
    if validation.authorization_decision_id:
        return str(validation.authorization_decision.asset.project_id)
    return None


def _scoped_actions(requested_by: str, *, include_risk_correlation: bool = True):
    projects = Project.objects.filter(Q(owner_id=requested_by) | Q(members__id=requested_by)).values('id')
    organizations = OrganizationMembership.objects.filter(user_id=requested_by, is_active=True).values('organization_id')
    queryset = DecisionAction.objects.filter(
        requested_by=requested_by,
        project_id__in=projects,
        organization_id__in=organizations,
    )
    if include_risk_correlation:
        queryset = queryset.select_related('risk_correlation')
    return queryset


def _validate_risk_correlation_lineage(
    decision: dict[str, Any],
    project: Project,
    validation: ValidationRun,
    risk_correlation: RiskCorrelationSnapshot | None,
) -> None:
    decision_correlation_id = decision.get("riskCorrelationId")
    if not decision_correlation_id:
        if risk_correlation is not None:
            raise ValueError("Decision has no risk-correlation lineage")
        return
    if risk_correlation is None:
        raise ValueError("Decision requires persisted risk-correlation lineage")
    if str(risk_correlation.id) != str(decision_correlation_id):
        raise ValueError("Decision risk-correlation id does not match the persisted snapshot")
    if str(risk_correlation.project_id) != str(project.id):
        raise ValueError("Risk-correlation project lineage does not match the action project")
    if not validation.finding_id or str(risk_correlation.vulnerability_id) != str(validation.finding_id):
        raise ValueError("Risk-correlation finding lineage does not match the action validation")
    if str(decision.get("riskCorrelationSha256") or "") != str(risk_correlation.correlation_sha256):
        raise ValueError("Decision risk-correlation SHA256 does not match the persisted snapshot")
    if str(decision.get("riskAnalysisVersion") or "") != str(risk_correlation.analysis_version):
        raise ValueError("Decision risk-correlation analysis version does not match the persisted snapshot")
    if str(decision.get("riskCorrelationPriority") or "") != str(risk_correlation.priority):
        raise ValueError("Decision risk-correlation priority does not match the persisted snapshot")
    decision_score = float(decision.get("riskCorrelationScore") or 0.0)
    if round(decision_score, 4) != round(float(risk_correlation.score), 4):
        raise ValueError("Decision risk-correlation score does not match the persisted snapshot")


def create_action(
    decision: dict[str, Any],
    owner: str,
    sla_hours: int,
    requested_by: str,
    *,
    organization: Organization,
    project: Project,
    validation: ValidationRun,
    risk_correlation: RiskCorrelationSnapshot | None = None,
) -> dict[str, Any]:
    if decision.get("actionable") is False:
        raise ValueError(str(decision.get("actionabilityReason") or "Decision is not actionable"))
    if str(validation.user_id) != str(requested_by):
        raise PermissionError("Validation does not belong to the requesting user")
    if _validation_project_id(validation) != str(project.id):
        raise ValueError("Validation project lineage does not match the action project")
    if not TenantProject.objects.filter(project=project, organization=organization).exists():
        raise ValueError("Project tenant lineage does not match the action organization")
    _validate_risk_correlation_lineage(decision, project, validation, risk_correlation)

    now = timezone.now()
    with transaction.atomic():
        action = DecisionAction.objects.create(
            organization=organization,
            project=project,
            validation=validation,
            risk_correlation=risk_correlation,
            action_id=f"act-{uuid4().hex[:12]}",
            decision_id=str(decision.get("decisionId") or ""),
            node_id=str(decision.get("nodeId") or "unknown"),
            title=f"Remediate: {decision.get('label', 'Security finding')}",
            owner=owner,
            requested_by=requested_by,
            sla_hours=max(1, sla_hours),
            state="pending",
            risk_before=int(decision.get("risk", 0) or 0),
            confidence_before=int(decision.get("confidence", 0) or 0),
            priority=int(decision.get("priority", 0) or 0),
            recommended_action=decision.get("recommendedAction", "Apply remediation and re-validate."),
            remediation_plan=decision.get("revalidationPlan", []),
            created_at=now,
            updated_at=now,
        )
        DecisionActionEvent.objects.create(
            action=action,
            event_type="action.created",
            actor=requested_by,
            created_at=now,
        )
    return _hydrate(
        DecisionAction.objects.select_related('risk_correlation').prefetch_related('events').get(pk=action.pk)
    )


def transition(action_id: str, state: str, actor: str, note: str | None = None) -> dict[str, Any]:
    if state not in STATES:
        raise ValueError(f"Invalid state: {state}")
    with transaction.atomic():
        # Lock only the DecisionAction row. Joining the nullable correlation FK
        # under SELECT ... FOR UPDATE creates an outer join that PostgreSQL
        # correctly refuses to lock.
        action = _scoped_actions(
            actor,
            include_risk_correlation=False,
        ).select_for_update().filter(pk=action_id).first()
        if action is None:
            raise KeyError(action_id)
        if state not in TRANSITIONS.get(action.state, set()):
            raise ValueError(f"Invalid transition: {action.state} -> {state}")
        now = timezone.now()
        action.state = state
        action.updated_at = now
        action.version += 1
        action.save(update_fields=['state', 'updated_at', 'version'])
        DecisionActionEvent.objects.create(
            action=action,
            event_type=f"action.{state}",
            actor=actor,
            note=note,
            created_at=now,
        )
    return _hydrate(_scoped_actions(actor).prefetch_related('events').get(pk=action.pk))


def list_actions(requested_by: str) -> list[dict[str, Any]]:
    rows = _scoped_actions(requested_by).prefetch_related('events').order_by('-updated_at')
    return [_hydrate(row) for row in rows]


def get_action(action_id: str, requested_by: str) -> dict[str, Any] | None:
    action = _scoped_actions(requested_by).filter(pk=action_id).prefetch_related('events').first()
    return _hydrate(action) if action else None
