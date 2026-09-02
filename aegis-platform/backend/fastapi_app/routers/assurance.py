from __future__ import annotations

from collections import defaultdict
from datetime import timezone
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.dependencies import get_current_user
from evidence.models import Evidence, ValidationRun

router = APIRouter()


class AssuranceSummary(BaseModel):
    conflicts: int
    signals: int
    sources: int
    agreement: int
    confidence: int


@sync_to_async
def _conflicts(user_id: str, limit: int):
    runs = ValidationRun.objects.filter(user_id=user_id, status=ValidationRun.Status.COMPLETED, finding__isnull=False).order_by('-completed_at')
    grouped = defaultdict(list)
    for run in runs[:1000]:
        result = run.result if isinstance(run.result, dict) else {}
        if 'finding_present' in result:
            grouped[str(run.finding_id)].append(run)
    items = []
    for finding_id, history in grouped.items():
        observed = {bool((run.result or {}).get('finding_present')) for run in history}
        if len(observed) < 2:
            continue
        items.append({
            'finding_id': finding_id,
            'type': 'validation_conflict',
            'confidence_impact': -20,
            'recommendation': 'Investigate conflicting validation results and rerun an authorized validation.',
            'validations': [
                {'id': str(run.id), 'finding_present': run.result.get('finding_present'), 'engine': (run.engines or [None])[0], 'completed_at': run.completed_at.astimezone(timezone.utc).isoformat() if run.completed_at else None}
                for run in history[:10]
            ],
        })
    return items[:limit]


@sync_to_async
def _summary_data(user_id: str):
    runs = list(ValidationRun.objects.filter(user_id=user_id, status=ValidationRun.Status.COMPLETED).order_by('-completed_at')[:1000])
    sources = set()
    agreement = 0
    for run in runs:
        sources.update(str(x) for x in (run.engines or []))
        result = run.result if isinstance(run.result, dict) else {}
        evidence_id = result.get('evidence_id')
        if evidence_id and Evidence.objects.filter(pk=evidence_id, finding=run.finding).exists():
            agreement += 1
    signal_count = len(runs)
    confidence = round(max(0.0, min(100.0, 50.0 + (agreement / signal_count * 50.0 if signal_count else 0.0))))
    return {'signals': signal_count, 'sources': len(sources), 'agreement': agreement, 'confidence': confidence}


@router.get('/correlations/conflicts')
async def list_conflicts(limit: int = Query(100, ge=1, le=500), current_user=Depends(get_current_user)):
    items = await _conflicts(str(current_user.get('user_id')), limit)
    return {'items': items, 'total': len(items), 'source': 'postgresql'}


@router.get('/correlations/summary', response_model=AssuranceSummary)
async def correlation_summary(current_user=Depends(get_current_user)):
    data = await _summary_data(str(current_user.get('user_id')))
    conflicts = len(await _conflicts(str(current_user.get('user_id')), 500))
    return {**data, 'conflicts': conflicts}


@router.get('/correlations/validations/{validation_id}')
async def validation_correlation(validation_id: UUID, current_user=Depends(get_current_user)):
    run = await sync_to_async(lambda: ValidationRun.objects.filter(id=validation_id, user_id=str(current_user.get('user_id'))).first())()
    if not run:
        raise HTTPException(status_code=404, detail='Validation not found')
    result = run.result if isinstance(run.result, dict) else {}
    evidence_id = result.get('evidence_id')
    evidence = None
    if evidence_id:
        evidence = await sync_to_async(lambda: Evidence.objects.filter(pk=evidence_id, finding=run.finding).first())()
    return {
        'validation_id': str(run.id),
        'finding_id': str(run.finding_id) if run.finding_id else None,
        'status': run.status,
        'engine': (run.engines or [None])[0],
        'finding_present': result.get('finding_present'),
        'evidence_id': str(evidence.id) if evidence else None,
        'evidence_valid': evidence is not None,
        'source': 'postgresql',
    }
