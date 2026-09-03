from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from django_project.assets.models import Asset
from django_project.compliance.models import ComplianceAssessment
from django_project.evidence.models import Evidence
from django_project.posture.models import PostureSnapshot
from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability

from ..core.dependencies import get_current_user

router = APIRouter()


class PostureResponse(BaseModel):
    id: str
    project_id: str
    overall_score: float
    rating: str
    metrics: List[dict]
    recommendations: List[str]
    created_at: str


class MetricResponse(BaseModel):
    name: str
    value: float
    max_value: float
    category: str
    trend: str
    percentage: float


class TrendResponse(BaseModel):
    metric_name: str
    snapshots: List[dict]
    direction: str
    change_rate: float


class EvaluationResponse(BaseModel):
    evaluation_id: str
    project_id: str
    overall_score: float
    rating: str
    created_at: str


_CLOSED_STATUSES = {
    Vulnerability.Status.FIXED,
    Vulnerability.Status.FALSE_POSITIVE,
    Vulnerability.Status.ACCEPTED_RISK,
    Vulnerability.Status.WONT_FIX,
    Vulnerability.Status.DUPLICATE,
}


def _rating(score: float) -> str:
    if score >= 90:
        return 'excellent'
    if score >= 75:
        return 'good'
    if score >= 60:
        return 'needs_attention'
    if score >= 40:
        return 'poor'
    return 'critical'


def _calculate(project_id: str) -> dict:
    project = Project.objects.filter(pk=project_id).first()
    if not project:
        raise ValueError('Project not found')

    assets = Asset.objects.filter(project_id=project_id)
    active_assets = assets.filter(is_active=True)
    total_assets = assets.count()
    active_asset_count = active_assets.count()
    scanned_assets = active_assets.filter(last_scanned_at__isnull=False).count()

    findings = Vulnerability.objects.filter(project_id=project_id)
    total_findings = findings.count()
    open_findings_qs = findings.exclude(status__in=_CLOSED_STATUSES)
    open_findings = open_findings_qs.count()

    severity_counts = {
        'critical': open_findings_qs.filter(severity=Vulnerability.Severity.CRITICAL).count(),
        'high': open_findings_qs.filter(severity=Vulnerability.Severity.HIGH).count(),
        'medium': open_findings_qs.filter(severity=Vulnerability.Severity.MEDIUM).count(),
        'low': open_findings_qs.filter(severity=Vulnerability.Severity.LOW).count(),
    }
    verified_findings = findings.filter(validation_status='verified').count()

    evidence_count = Evidence.objects.filter(
        Q(asset__project_id=project_id) | Q(finding__project_id=project_id)
    ).distinct().count()
    verified_evidence_count = Evidence.objects.filter(
        Q(asset__project_id=project_id) | Q(finding__project_id=project_id),
        metadata__finding_present=False,
    ).distinct().count()

    assessed = ComplianceAssessment.objects.filter(project_id=project_id).exclude(
        status=ComplianceAssessment.Status.NOT_ASSESSED
    )
    assessed_count = assessed.count()
    compliant_count = assessed.filter(status=ComplianceAssessment.Status.COMPLIANT).count()

    weighted_open = (
        severity_counts['critical'] * 4
        + severity_counts['high'] * 3
        + severity_counts['medium'] * 2
        + severity_counts['low']
    )
    vulnerability_health = max(0.0, 100.0 - min(100.0, (weighted_open * 100.0) / max(active_asset_count * 4, 1)))
    control_effectiveness = 100.0 * compliant_count / assessed_count if assessed_count else 0.0
    evidence_quality = 100.0 * verified_evidence_count / evidence_count if evidence_count else 0.0
    coverage = 100.0 * scanned_assets / active_asset_count if active_asset_count else 0.0
    overall_score = round(
        vulnerability_health * 0.35
        + control_effectiveness * 0.25
        + evidence_quality * 0.20
        + coverage * 0.20,
        2,
    )

    recommendations: list[str] = []
    if severity_counts['critical'] or severity_counts['high']:
        recommendations.append('Prioritize open critical and high severity findings.')
    if coverage < 100:
        recommendations.append('Run assessments for active assets without a recorded scan.')
    if control_effectiveness < 80:
        recommendations.append('Assess or remediate compliance controls with non-compliant or partial status.')
    if evidence_quality < 80:
        recommendations.append('Increase validated evidence coverage for findings and controls.')
    if not recommendations:
        recommendations.append('Maintain the current security posture and continue periodic validation.')

    return {
        'project_id': str(project_id),
        'overall_score': overall_score,
        'rating': _rating(overall_score),
        'metrics': [
            {'name': 'Vulnerability Health', 'value': round(vulnerability_health, 2), 'max_value': 100, 'category': 'vulnerabilities', 'trend': 'current', 'percentage': round(vulnerability_health, 2)},
            {'name': 'Control Effectiveness', 'value': round(control_effectiveness, 2), 'max_value': 100, 'category': 'controls', 'trend': 'current', 'percentage': round(control_effectiveness, 2)},
            {'name': 'Evidence Quality', 'value': round(evidence_quality, 2), 'max_value': 100, 'category': 'evidence', 'trend': 'current', 'percentage': round(evidence_quality, 2)},
            {'name': 'Coverage', 'value': round(coverage, 2), 'max_value': 100, 'category': 'coverage', 'trend': 'current', 'percentage': round(coverage, 2)},
        ],
        'recommendations': recommendations,
        'created_at': datetime.utcnow().isoformat(),
        'counts': {
            'total_assets': total_assets,
            'active_assets': active_asset_count,
            'scanned_assets': scanned_assets,
            'total_findings': total_findings,
            'open_findings': open_findings,
            'critical_findings': severity_counts['critical'],
            'high_findings': severity_counts['high'],
            'medium_findings': severity_counts['medium'],
            'low_findings': severity_counts['low'],
            'verified_findings': verified_findings,
            'evidence_count': evidence_count,
        },
    }


@sync_to_async
def _authorized_project(project_id: str, user_id: str) -> bool:
    project = Project.objects.filter(pk=project_id).first()
    return bool(project and (str(project.owner_id) == str(user_id) or project.members.filter(pk=user_id).exists()))


@sync_to_async
def _current_posture(project_id: str) -> dict:
    return _calculate(project_id)


@sync_to_async
def _create_snapshot(project_id: str, user_id: str) -> PostureSnapshot:
    data = _calculate(project_id)
    counts = data['counts']
    metrics = {m['category']: m['value'] for m in data['metrics']}
    return PostureSnapshot.objects.create(
        project_id=project_id,
        created_by_id=user_id,
        overall_score=data['overall_score'],
        rating=data['rating'],
        vulnerability_health=metrics['vulnerabilities'],
        control_effectiveness=metrics['controls'],
        evidence_quality=metrics['evidence'],
        coverage=metrics['coverage'],
        **counts,
    )


@sync_to_async
def _history(project_id: str, limit: int) -> list[PostureSnapshot]:
    return list(PostureSnapshot.objects.filter(project_id=project_id).order_by('-created_at')[:limit])


@sync_to_async
def _compare(project_id: str, period_a_start: str, period_a_end: str, period_b_start: str, period_b_end: str) -> dict:
    qs = PostureSnapshot.objects.filter(project_id=project_id)
    a = list(qs.filter(created_at__gte=period_a_start, created_at__lte=period_a_end).order_by('created_at'))
    b = list(qs.filter(created_at__gte=period_b_start, created_at__lte=period_b_end).order_by('created_at'))
    if not a or not b:
        raise ValueError('Both comparison periods require persisted posture snapshots')
    a_avg = sum(s.overall_score for s in a) / len(a)
    b_avg = sum(s.overall_score for s in b) / len(b)
    change = round(b_avg - a_avg, 2)
    return {'period_a_avg': round(a_avg, 2), 'period_b_avg': round(b_avg, 2), 'change': change, 'improvement': change > 0}


@router.get('/projects/{project_id}/posture', response_model=PostureResponse)
async def get_posture(project_id: str, current_user=Depends(get_current_user)):
    if not await _authorized_project(project_id, str(current_user.get('user_id'))):
        raise HTTPException(status_code=403, detail='Project access denied')
    try:
        data = await _current_posture(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return PostureResponse(id=f'current-{project_id}', **{k: data[k] for k in ('project_id', 'overall_score', 'rating', 'metrics', 'recommendations', 'created_at')})


@router.get('/projects/{project_id}/metrics', response_model=List[MetricResponse])
async def get_metrics(project_id: str, current_user=Depends(get_current_user)):
    if not await _authorized_project(project_id, str(current_user.get('user_id'))):
        raise HTTPException(status_code=403, detail='Project access denied')
    try:
        data = await _current_posture(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return [MetricResponse(**metric) for metric in data['metrics']]


@router.get('/projects/{project_id}/trend', response_model=TrendResponse)
async def get_trend(project_id: str, metric_name: Optional[str] = None, periods: int = Query(10, ge=1, le=100), current_user=Depends(get_current_user)):
    if not await _authorized_project(project_id, str(current_user.get('user_id'))):
        raise HTTPException(status_code=403, detail='Project access denied')
    snapshots = await _history(project_id, periods)
    key = (metric_name or 'overall').lower().replace(' ', '_')
    values = []
    for snapshot in reversed(snapshots):
        value = snapshot.overall_score
        if key in {'vulnerability_health', 'vulnerability'}:
            value = snapshot.vulnerability_health
        elif key in {'control_effectiveness', 'controls', 'control'}:
            value = snapshot.control_effectiveness
        elif key in {'evidence_quality', 'evidence'}:
            value = snapshot.evidence_quality
        elif key == 'coverage':
            value = snapshot.coverage
        values.append({'timestamp': snapshot.created_at.isoformat(), 'value': round(value, 2)})
    if len(values) < 2:
        direction = 'insufficient_data'
        change_rate = 0.0
    else:
        delta = values[-1]['value'] - values[0]['value']
        direction = 'improving' if delta > 0 else 'declining' if delta < 0 else 'stable'
        change_rate = round(delta, 2)
    return TrendResponse(metric_name=metric_name or 'overall', snapshots=values, direction=direction, change_rate=change_rate)


@router.post('/projects/{project_id}/evaluate', response_model=EvaluationResponse)
async def evaluate_posture(project_id: str, current_user=Depends(get_current_user)):
    user_id = str(current_user.get('user_id'))
    if not await _authorized_project(project_id, user_id):
        raise HTTPException(status_code=403, detail='Project access denied')
    try:
        snapshot = await _create_snapshot(project_id, user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return EvaluationResponse(evaluation_id=str(snapshot.id), project_id=project_id, overall_score=snapshot.overall_score, rating=snapshot.rating, created_at=snapshot.created_at.isoformat())


@router.get('/projects/{project_id}/compare')
async def compare_periods(project_id: str, period_a_start: str, period_a_end: str, period_b_start: str, period_b_end: str, current_user=Depends(get_current_user)):
    if not await _authorized_project(project_id, str(current_user.get('user_id'))):
        raise HTTPException(status_code=403, detail='Project access denied')
    try:
        return await _compare(project_id, period_a_start, period_a_end, period_b_start, period_b_end)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get('/projects/{project_id}/history')
async def get_history(project_id: str, limit: int = Query(30, ge=1, le=100), current_user=Depends(get_current_user)):
    if not await _authorized_project(project_id, str(current_user.get('user_id'))):
        raise HTTPException(status_code=403, detail='Project access denied')
    snapshots = await _history(project_id, limit)
    return [{'timestamp': snapshot.created_at.isoformat(), 'overall_score': snapshot.overall_score, 'rating': snapshot.rating, 'snapshot_id': str(snapshot.id)} for snapshot in snapshots]
