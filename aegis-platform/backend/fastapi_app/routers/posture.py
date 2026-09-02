from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.dependencies import get_current_user
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from django_project.compliance.models import ComplianceAssessment

router = APIRouter()


class PostureResponse(BaseModel):
    id: str
    project_id: str
    overall_score: float
    rating: str
    metrics: list[dict]
    recommendations: list[str]
    created_at: str
    source: str
    scan_id: Optional[str] = None


class MetricResponse(BaseModel):
    name: str
    value: float
    max_value: float
    category: str
    trend: str
    percentage: float


class TrendResponse(BaseModel):
    metric_name: str
    snapshots: list[dict]
    direction: str
    change_rate: float


_INACTIVE = {
    Vulnerability.Status.FIXED,
    Vulnerability.Status.FALSE_POSITIVE,
    Vulnerability.Status.ACCEPTED_RISK,
    Vulnerability.Status.WONT_FIX,
    Vulnerability.Status.DUPLICATE,
}


def _score_for_findings(findings) -> float:
    weights = {
        Vulnerability.Severity.CRITICAL: 35.0,
        Vulnerability.Severity.HIGH: 20.0,
        Vulnerability.Severity.MEDIUM: 10.0,
        Vulnerability.Severity.LOW: 3.0,
        Vulnerability.Severity.INFO: 0.5,
    }
    penalty = sum(weights.get(item.severity, 0.0) for item in findings if item.status not in _INACTIVE)
    return round(max(0.0, min(100.0, 100.0 - penalty)), 2)


def _rating(score: float) -> str:
    if score >= 90: return 'excellent'
    if score >= 75: return 'good'
    if score >= 60: return 'fair'
    if score >= 40: return 'poor'
    return 'critical'


@sync_to_async
def _project(user_id: str, project_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return project


@sync_to_async
def _posture(project_id: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    findings = list(Vulnerability.objects.filter(project=project).only('severity', 'status', 'evidence_count'))
    assets_total = project.assets.count()
    assets_scanned = project.scans.filter(status=Scan.Status.COMPLETED).values('asset_id').distinct().count()
    active = [f for f in findings if f.status not in _INACTIVE]
    evidence_quality = round(sum(1 for f in findings if f.evidence_count > 0) / len(findings) * 100, 2) if findings else 100.0
    coverage = round(assets_scanned / assets_total * 100, 2) if assets_total else 0.0
    assessments = ComplianceAssessment.objects.filter(project=project).exclude(status=ComplianceAssessment.Status.NOT_ASSESSED)
    compliant = assessments.filter(status=ComplianceAssessment.Status.COMPLIANT).count()
    partial = assessments.filter(status=ComplianceAssessment.Status.PARTIAL).count()
    controls = round(((compliant + partial * 0.5) / assessments.count()) * 100, 2) if assessments.exists() else 0.0
    score = _score_for_findings(findings)
    recommendations = []
    if any(f.severity in {Vulnerability.Severity.CRITICAL, Vulnerability.Severity.HIGH} for f in active): recommendations.append('Remediate open critical and high severity findings.')
    if evidence_quality < 100: recommendations.append('Collect evidence for findings that have no evidence records.')
    if coverage < 100: recommendations.append('Run authorized assessments for assets without completed scans.')
    if assessments.exists() and controls < 100: recommendations.append('Address partial and non-compliant controls.')
    latest = Scan.objects.filter(project=project, status=Scan.Status.COMPLETED).order_by('-completed_at', '-created_at').first()
    timestamp = (latest.completed_at or latest.created_at) if latest else datetime.now(timezone.utc)
    return {'id': f'scan:{latest.id}' if latest else f'project:{project.id}', 'project_id': str(project.id), 'overall_score': score, 'rating': _rating(score),
            'metrics': [
                {'name': 'Vulnerability Health', 'value': round(max(0.0, 100.0 - len(active) * 5.0), 2), 'max_value': 100, 'category': 'vulnerabilities', 'trend': 'data-derived'},
                {'name': 'Control Effectiveness', 'value': controls, 'max_value': 100, 'category': 'controls', 'trend': 'data-derived'},
                {'name': 'Evidence Quality', 'value': evidence_quality, 'max_value': 100, 'category': 'evidence', 'trend': 'data-derived'},
                {'name': 'Coverage', 'value': coverage, 'max_value': 100, 'category': 'coverage', 'trend': 'data-derived'}],
            'recommendations': recommendations, 'created_at': timestamp.astimezone(timezone.utc).isoformat(), 'source': 'postgresql', 'scan_id': str(latest.id) if latest else None}


@sync_to_async
def _history(project_id: str, user_id: str, limit: int):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    rows = []
    for scan in Scan.objects.filter(project=project, status=Scan.Status.COMPLETED).order_by('-completed_at', '-created_at')[:limit]:
        score = _score_for_findings(list(Vulnerability.objects.filter(scan=scan).only('severity', 'status')))
        timestamp = scan.completed_at or scan.created_at
        rows.append({'scan_id': str(scan.id), 'timestamp': timestamp.astimezone(timezone.utc).isoformat(), 'overall_score': score, 'rating': _rating(score)})
    return list(reversed(rows))


@router.get('/projects/{project_id}/posture', response_model=PostureResponse)
async def get_posture(project_id: str, current_user=Depends(get_current_user)):
    return await _posture(project_id, str(current_user.get('user_id')))

@router.get('/projects/{project_id}/metrics', response_model=list[MetricResponse])
async def get_metrics(project_id: str, current_user=Depends(get_current_user)):
    posture = await _posture(project_id, str(current_user.get('user_id')))
    return [MetricResponse(**metric, percentage=metric['value']) for metric in posture['metrics']]

@router.get('/projects/{project_id}/trend', response_model=TrendResponse)
async def get_trend(project_id: str, metric_name: Optional[str] = None, periods: int = Query(10, ge=1, le=100), current_user=Depends(get_current_user)):
    history = await _history(project_id, str(current_user.get('user_id')), periods)
    values = [float(item['overall_score']) for item in history]
    change_rate = round(values[-1] - values[0], 2) if len(values) >= 2 else 0.0
    return TrendResponse(metric_name=metric_name or 'overall', snapshots=history, direction='improving' if change_rate > 0 else 'declining' if change_rate < 0 else 'stable', change_rate=change_rate)

@router.post('/projects/{project_id}/evaluate')
async def evaluate_posture(project_id: str, current_user=Depends(get_current_user)):
    return {'status': 'completed', 'source': 'postgresql', 'posture': await _posture(project_id, str(current_user.get('user_id')))}

@router.get('/projects/{project_id}/compare')
async def compare_periods(project_id: str, period_a_start: str, period_a_end: str, period_b_start: str, period_b_end: str, current_user=Depends(get_current_user)):
    history = await _history(project_id, str(current_user.get('user_id')), 100)
    a = [x['overall_score'] for x in history if period_a_start <= x['timestamp'][:10] <= period_a_end]
    b = [x['overall_score'] for x in history if period_b_start <= x['timestamp'][:10] <= period_b_end]
    if not a or not b: raise HTTPException(status_code=404, detail='Insufficient completed scan data for requested periods')
    avg_a, avg_b = round(sum(a) / len(a), 2), round(sum(b) / len(b), 2)
    return {'period_a_avg': avg_a, 'period_b_avg': avg_b, 'change': round(avg_b - avg_a, 2), 'improvement': avg_b > avg_a}

@router.get('/projects/{project_id}/history')
async def get_history(project_id: str, limit: int = Query(30, ge=1, le=100), current_user=Depends(get_current_user)):
    return await _history(project_id, str(current_user.get('user_id')), limit)
