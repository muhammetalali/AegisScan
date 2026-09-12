from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException

from ..core.dependencies import get_current_user
from ..services.assurance_correlation import correlate_all, correlate_validation
from ..services.assurance_graph_aggregator import build_assurance_graph
from ..services.graph_intelligence import analyze_graph
from ..services.autonomous_triage import triage_graph
from django_project.evidence.models import ValidationRun
from enterprise.models import RiskCorrelationSnapshot

router = APIRouter()


@sync_to_async
def _load_validations(user_id: str) -> dict[str, dict[str, Any]]:
    rows = list(
        ValidationRun.objects.filter(user_id=user_id)
        .select_related('finding__scan', 'finding__project', 'authorization_decision__asset__project')
        .order_by('-created_at')
    )
    finding_ids = [item.finding_id for item in rows if item.finding_id]
    risk_by_finding: dict[str, RiskCorrelationSnapshot] = {}
    if finding_ids:
        for snapshot in (
            RiskCorrelationSnapshot.objects
            .filter(vulnerability_id__in=finding_ids)
            .order_by('vulnerability_id', '-created_at', '-id')
        ):
            risk_by_finding.setdefault(str(snapshot.vulnerability_id), snapshot)

    result: dict[str, dict[str, Any]] = {}
    for item in rows:
        project = item.finding.project if item.finding_id else None
        if project is None and item.authorization_decision_id:
            project = item.authorization_decision.asset.project
        engines = [str(engine).lower() for engine in (item.engines or [])]
        engine_state: dict[str, dict[str, int]] = {}
        if item.finding_id and item.finding and item.finding.scan_id:
            for execution in item.finding.scan.engine_executions.select_related('engine').all():
                engine_state[execution.engine.name] = {
                    'findings': int(execution.findings_found or 0),
                    'evidence': int(execution.evidences_collected or 0),
                }
        risk_snapshot = risk_by_finding.get(str(item.finding_id)) if item.finding_id else None
        risk_components = risk_snapshot.components if risk_snapshot and isinstance(risk_snapshot.components, dict) else {}
        result[str(item.id)] = {
            'status': item.status,
            'progress': int(item.progress or 0),
            'engines': engines,
            'engines_state': engine_state,
            'target_type': item.target_type,
            'target_value': item.target_value,
            'scope': item.scope,
            'finding_id': str(item.finding_id) if item.finding_id else None,
            'validation_id': str(item.id),
            'project_id': str(project.id) if project else None,
            'risk_correlation': {
                'id': str(risk_snapshot.id),
                'sha256': risk_snapshot.correlation_sha256,
                'analysis_version': risk_snapshot.analysis_version,
                'score': float(risk_snapshot.score),
                'priority': risk_snapshot.priority,
                'intelligence_confidence': float(risk_components.get('intelligence_confidence') or 0.0),
                'intelligence_conflict': bool(risk_components.get('intelligence_conflict')),
                'supporting_evidence_count': int(risk_components.get('supporting_evidence_count') or 0),
                'contradicting_evidence_count': int(risk_components.get('contradicting_evidence_count') or 0),
                'neutral_evidence_count': int(risk_components.get('neutral_evidence_count') or 0),
            } if risk_snapshot else None,
        }
    return result


@sync_to_async
def _load_validation(validation_id: str, user_id: str):
    item = ValidationRun.objects.filter(id=validation_id, user_id=user_id).select_related('finding__scan', 'finding__project').first()
    return item


def _build(validations: dict[str, dict[str, Any]], correlations: dict[str, Any] | None = None) -> dict[str, Any]:
    graph = analyze_graph(build_assurance_graph(validations, correlations))
    graph['triage'] = triage_graph(graph)
    return graph


async def require_user(user=Depends(get_current_user)):
    return user


@router.get('/graph')
async def assurance_graph(user=Depends(require_user)):
    validations = await _load_validations(str(user.get('user_id')))
    correlations = correlate_all(validations)
    return _build(validations, correlations)


@router.get('/graph/validations/{validation_id}')
async def assurance_graph_validation(validation_id: str, user=Depends(require_user)):
    validation = await _load_validation(validation_id, str(user.get('user_id')))
    if validation is None:
        raise HTTPException(status_code=404, detail='Validation not found')
    risk_snapshot = None
    if validation.finding_id:
        risk_snapshot = await sync_to_async(
            lambda: RiskCorrelationSnapshot.objects.filter(vulnerability_id=validation.finding_id)
            .order_by('-created_at', '-id').first()
        )()
    risk_components = risk_snapshot.components if risk_snapshot and isinstance(risk_snapshot.components, dict) else {}
    item = {
        str(validation.id): {
            'status': validation.status,
            'progress': int(validation.progress or 0),
            'engines': [str(engine).lower() for engine in (validation.engines or [])],
            'engines_state': {},
            'target_type': validation.target_type,
            'target_value': validation.target_value,
            'scope': validation.scope,
            'finding_id': str(validation.finding_id) if validation.finding_id else None,
            'validation_id': str(validation.id),
            'project_id': str(validation.finding.project_id) if validation.finding_id else None,
            'risk_correlation': {
                'id': str(risk_snapshot.id),
                'sha256': risk_snapshot.correlation_sha256,
                'analysis_version': risk_snapshot.analysis_version,
                'score': float(risk_snapshot.score),
                'priority': risk_snapshot.priority,
                'intelligence_confidence': float(risk_components.get('intelligence_confidence') or 0.0),
                'intelligence_conflict': bool(risk_components.get('intelligence_conflict')),
                'supporting_evidence_count': int(risk_components.get('supporting_evidence_count') or 0),
                'contradicting_evidence_count': int(risk_components.get('contradicting_evidence_count') or 0),
                'neutral_evidence_count': int(risk_components.get('neutral_evidence_count') or 0),
            } if risk_snapshot else None,
        }
    }
    if validation.finding_id and validation.finding and validation.finding.scan_id:
        item[str(validation.id)]['engines_state'] = {
            execution.engine.name: {
                'findings': int(execution.findings_found or 0),
                'evidence': int(execution.evidences_collected or 0),
            }
            for execution in validation.finding.scan.engine_executions.select_related('engine').all()
        }
    correlation = correlate_validation(validation_id, item[str(validation.id)])
    return _build(item, {'items': correlation.get('conflicts', [])})


@router.get('/triage')
async def assurance_triage(user=Depends(require_user)):
    validations = await _load_validations(str(user.get('user_id')))
    correlations = correlate_all(validations)
    graph = analyze_graph(build_assurance_graph(validations, correlations))
    return triage_graph(graph)
