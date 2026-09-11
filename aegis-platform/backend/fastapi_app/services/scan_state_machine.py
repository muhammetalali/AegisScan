from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from celery.result import AsyncResult
from django.db import transaction

from django_project.scans.models import Scan
from fastapi_app.services.enterprise_gap_closure import checkpoint_scan


ALLOWED = {
    Scan.Status.PENDING: {Scan.Status.QUEUED, Scan.Status.CANCELLED},
    Scan.Status.QUEUED: {Scan.Status.RUNNING, Scan.Status.CANCELLED},
    Scan.Status.RUNNING: {Scan.Status.PAUSED, Scan.Status.CANCELLED, Scan.Status.COMPLETED, Scan.Status.FAILED, Scan.Status.PARTIAL},
    Scan.Status.PAUSED: {Scan.Status.RUNNING, Scan.Status.CANCELLED},
    Scan.Status.FAILED: {Scan.Status.QUEUED},
    Scan.Status.CANCELLED: {Scan.Status.QUEUED},
    Scan.Status.PARTIAL: {Scan.Status.QUEUED},
    Scan.Status.COMPLETED: {Scan.Status.QUEUED},
}


def runtime_state(scan_id: str) -> str:
    state = Scan.objects.filter(pk=scan_id).values_list('status', flat=True).first()
    return str(state or Scan.Status.CANCELLED)


@transaction.atomic
def transition_scan(*, scan_id: str, user_id: str, target_status: str, reason: str = '') -> dict[str, Any]:
    scan = Scan.objects.select_for_update().select_related('project').filter(pk=scan_id).first()
    if scan is None:
        return {'status':'error','message':'Scan not found'}
    if not (str(scan.project.owner_id)==str(user_id) or scan.project.members.filter(pk=user_id).exists()):
        return {'status':'error','message':'Scan access denied'}
    if target_status not in ALLOWED.get(scan.status,set()):
        return {'status':'error','message':f'Invalid scan state transition: {scan.status} -> {target_status}'}
    previous=scan.status
    scan.status=target_status
    if target_status==Scan.Status.CANCELLED:
        scan.completed_at=datetime.now(timezone.utc)
    scan.save(update_fields=['status','completed_at','updated_at'])
    checkpoint=checkpoint_scan(scan,state=target_status,metadata={'reason':reason,'previous_status':previous,'actor_id':str(user_id)})
    if target_status==Scan.Status.CANCELLED and scan.celery_task_id:
        AsyncResult(scan.celery_task_id).revoke(terminate=False)
    return {'status':target_status,'previous_status':previous,'checkpoint_id':str(checkpoint.id),'resume_token':str(checkpoint.resume_token)}


@transaction.atomic
def prepare_restart(*, scan_id: str, user_id: str) -> dict[str, Any]:
    scan=Scan.objects.select_for_update().select_related('project').filter(pk=scan_id).first()
    if scan is None:
        return {'status':'error','message':'Scan not found'}
    if not (str(scan.project.owner_id)==str(user_id) or scan.project.members.filter(pk=user_id).exists()):
        return {'status':'error','message':'Scan access denied'}
    if scan.status not in {Scan.Status.FAILED,Scan.Status.CANCELLED,Scan.Status.PARTIAL,Scan.Status.COMPLETED}:
        return {'status':'error','message':'Only terminal scans can be restarted'}
    previous=scan.status
    checkpoint=checkpoint_scan(scan,state=previous,metadata={'restart_requested_by':str(user_id)})
    scan.status=Scan.Status.PENDING
    scan.progress=0
    scan.completed_at=None
    scan.error_message=''
    scan.current_phase='restart_pending'
    scan.save(update_fields=['status','progress','completed_at','error_message','current_phase','updated_at'])
    return {'status':'restart_ready','previous_status':previous,'checkpoint_id':str(checkpoint.id)}
