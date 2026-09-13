from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.db import transaction

from django_project.evidence.models import Evidence, FindingDisposition
from django_project.vulnerabilities.models import Vulnerability
from enterprise.assurance_models import AssuranceConditionState, AssuranceObservation
from enterprise.models import ContinuousAssuranceExecution, OrganizationMembership, TenantProject
from enterprise.soc_models import InvestigationClosure


_AUTHOR_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
    OrganizationMembership.Role.ANALYST,
}


class AssuranceDriftError(ValueError):
    pass


@dataclass(frozen=True)
class AssuranceObservationResult:
    observation: AssuranceObservation
    state: AssuranceConditionState
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _membership(project_id: str, user_id: str):
    link = TenantProject.objects.select_related('organization', 'project').filter(project_id=project_id).first()
    if link is None:
        raise AssuranceDriftError('Project is not bound to an enterprise tenant.')
    membership = OrganizationMembership.objects.filter(
        organization=link.organization,
        user_id=user_id,
        is_active=True,
        user__is_active=True,
        role__in=_AUTHOR_ROLES,
    ).first()
    if membership is None:
        raise PermissionError('Active tenant role does not permit assurance governance mutation.')
    return link


def record_assurance_observation(
    *,
    execution_id: str,
    project_id: str,
    finding_id: str,
    user_id: str,
    finding_present: bool,
    material: dict[str, Any],
    evidence_id: str | None = None,
) -> AssuranceObservationResult:
    if not isinstance(material, dict):
        raise AssuranceDriftError('material must be an object.')
    link = _membership(project_id, user_id)
    with transaction.atomic():
        TenantProject.objects.select_for_update().get(pk=link.pk)
        execution = ContinuousAssuranceExecution.objects.select_for_update().filter(
            pk=execution_id,
            project_id=project_id,
            organization=link.organization,
        ).first()
        if execution is None:
            raise AssuranceDriftError('Continuous assurance execution not found in tenant/project.')
        if execution.status != ContinuousAssuranceExecution.Status.COMPLETED:
            raise AssuranceDriftError('Only completed continuous assurance executions may produce governed observations.')
        finding = Vulnerability.objects.select_related('asset', 'scan').filter(pk=finding_id, asset_id=execution.asset_id).first()
        if finding is None:
            raise AssuranceDriftError('Finding is outside the assurance execution asset scope.')
        evidence = None
        if evidence_id:
            evidence = Evidence.objects.filter(pk=evidence_id, finding=finding, asset_id=execution.asset_id).first()
            if evidence is None:
                raise AssuranceDriftError('Evidence is outside the finding/execution lineage.')
        if finding_present and evidence is None:
            raise AssuranceDriftError('Present findings require evidence-backed observation lineage.')

        material_sha = _sha(material)
        payload = {
            'finding_present': bool(finding_present),
            'material': material,
            'evidence_id': str(evidence.id) if evidence else None,
        }
        payload_sha = _sha(payload)
        fingerprint = _sha({
            'execution_id': str(execution.id),
            'finding_id': str(finding.id),
            'payload_sha256': payload_sha,
        })
        existing = AssuranceObservation.objects.select_related('finding__assurance_condition_state').filter(replay_fingerprint=fingerprint).first()
        if existing:
            return AssuranceObservationResult(existing, existing.finding.assurance_condition_state, True)
        if AssuranceObservation.objects.filter(execution=execution, finding=finding).exists():
            raise AssuranceDriftError('This execution already has a governed observation for the finding.')

        condition_key = _sha({'project_id': str(project_id), 'asset_id': str(execution.asset_id), 'finding_id': str(finding.id)})
        state = AssuranceConditionState.objects.select_for_update().filter(project_id=project_id, finding=finding).first()
        if state is None:
            classification = AssuranceObservation.Classification.NEW if finding_present else AssuranceObservation.Classification.RESOLVED
            state = AssuranceConditionState.objects.create(
                organization=link.organization,
                project_id=project_id,
                asset_id=execution.asset_id,
                finding=finding,
                condition_key=condition_key,
                state=AssuranceConditionState.State.ACTIVE if finding_present else AssuranceConditionState.State.RESOLVED,
                generation=1,
                version=1,
                material_sha256=material_sha,
                last_execution=execution,
            )
        else:
            old_state = state.state
            if old_state == AssuranceConditionState.State.RESOLVED and finding_present:
                classification = AssuranceObservation.Classification.RECURRENT
                state.generation += 1
                state.state = AssuranceConditionState.State.ACTIVE
            elif old_state == AssuranceConditionState.State.ACTIVE and not finding_present:
                classification = AssuranceObservation.Classification.RESOLVED
                state.state = AssuranceConditionState.State.RESOLVED
            elif finding_present and state.material_sha256 != material_sha:
                classification = AssuranceObservation.Classification.CHANGED
            else:
                classification = AssuranceObservation.Classification.STABLE
            state.version += 1
            state.material_sha256 = material_sha
            state.last_execution = execution
            state.save(update_fields=['state', 'generation', 'version', 'material_sha256', 'last_execution', 'updated_at'])

        prior_closure = None
        prior_disposition = None
        if classification == AssuranceObservation.Classification.RECURRENT:
            prior_closure = InvestigationClosure.objects.filter(finding=finding).order_by('-closed_at').first()
            prior_disposition = FindingDisposition.objects.filter(finding=finding).order_by('-created_at').first()

        observation = AssuranceObservation.objects.create(
            organization=link.organization,
            project_id=project_id,
            asset_id=execution.asset_id,
            execution=execution,
            finding=finding,
            classification=classification,
            generation=state.generation,
            state_version=state.version,
            finding_present=finding_present,
            material_sha256=material_sha,
            payload_sha256=payload_sha,
            replay_fingerprint=fingerprint,
            evidence=evidence,
            prior_closure=prior_closure,
            prior_disposition=prior_disposition,
            payload=payload,
            observed_by_id=user_id,
        )
        if classification == AssuranceObservation.Classification.RECURRENT:
            from fastapi_app.services.assurance_obligation_governance import materialize_recurrence_obligation
            materialize_recurrence_obligation(
                project_id=project_id,
                observation_id=str(observation.id),
                user_id=user_id,
            )
        return AssuranceObservationResult(observation, state, False)


def get_assurance_condition(*, project_id: str, finding_id: str, user_id: str) -> dict[str, Any]:
    _membership(project_id, user_id)
    state = AssuranceConditionState.objects.filter(project_id=project_id, finding_id=finding_id).first()
    if state is None:
        raise AssuranceDriftError('Governed assurance condition not found.')
    latest = AssuranceObservation.objects.filter(finding_id=finding_id, project_id=project_id).order_by('-observed_at').first()
    return {
        'finding_id': str(finding_id),
        'state': state.state,
        'generation': state.generation,
        'version': state.version,
        'material_sha256': state.material_sha256,
        'last_execution_id': str(state.last_execution_id) if state.last_execution_id else None,
        'latest_classification': latest.classification if latest else None,
        'governance_drift': bool(latest and latest.classification == AssuranceObservation.Classification.RECURRENT and (latest.prior_closure_id or latest.prior_disposition_id)),
    }