from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from psycopg2.pool import ThreadedConnectionPool
from django.db import transaction

from django_project.audit.models import AuditLog
from django_project.evidence.models import ValidationRun
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityStatusHistory
from fastapi_app.tasks.nmap_finding_validation import validate_nmap_finding_e2e

from ..core.config import settings

_pool: ThreadedConnectionPool | None = None
_schema_ready = False


def _now():
    return datetime.now(timezone.utc)


def _db():
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(1, 8, settings.DATABASE_URL)
    return _pool


def _ensure_schema():
    global _schema_ready
    if _schema_ready:
        return
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """CREATE TABLE IF NOT EXISTS remediation_runs (
                    remediation_id TEXT PRIMARY KEY,
                    finding_id UUID NOT NULL,
                    validation_id UUID NOT NULL,
                    actor TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    risk_before DOUBLE PRECISION NOT NULL,
                    risk_after DOUBLE PRECISION,
                    risk_delta DOUBLE PRECISION,
                    evidence_id UUID,
                    reason TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    completed_at TIMESTAMPTZ
                )"""
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_remediation_finding_created ON remediation_runs(finding_id, created_at)")
            conn.commit()
            _schema_ready = True
    finally:
        pool.putconn(conn)


def _insert_run(row: dict):
    _ensure_schema()
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO remediation_runs
                (remediation_id,finding_id,validation_id,actor,action_type,state,risk_before,risk_after,risk_delta,evidence_id,reason,created_at,completed_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    row['remediation_id'], row['finding_id'], row['validation_id'], row['actor'],
                    row['action_type'], row['state'], row['risk_before'], row['risk_after'], row['risk_delta'],
                    row['evidence_id'], row['reason'], row['created_at'], row['completed_at'],
                ),
            )
            conn.commit()
    finally:
        pool.putconn(conn)


def get_run(remediation_id: str) -> dict | None:
    _ensure_schema()
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM remediation_runs WHERE remediation_id=%s", (remediation_id,))
            row = cur.fetchone()
            if not row:
                return None
            keys = ['remediation_id','finding_id','validation_id','actor','action_type','state','risk_before','risk_after','risk_delta','evidence_id','reason','created_at','completed_at']
            result = dict(zip(keys, row))
            for key in ('finding_id','validation_id','evidence_id'):
                if result[key] is not None:
                    result[key] = str(result[key])
            result['created_at'] = result['created_at'].isoformat()
            result['completed_at'] = result['completed_at'].isoformat() if result['completed_at'] else None
            return result
    finally:
        pool.putconn(conn)


def execute_validated_closure(finding_id: str, actor_id: str, reason: str) -> dict:
    with transaction.atomic():
        finding = (
            Vulnerability.objects.select_for_update(of=('self',))
            .select_related('asset', 'scan')
            .filter(pk=finding_id)
            .first()
        )
        if not finding:
            raise ValueError('Finding not found')
        if finding.status == Vulnerability.Status.FIXED:
            raise ValueError('Finding is already fixed')
        if not finding.asset_id or not finding.scan_id:
            raise ValueError('Finding must retain asset and originating scan lineage')
        if (finding.source_engine or '').strip().lower() != 'nmap':
            raise ValueError('Validated closure currently supports only Nmap findings')
        authorization_id = finding.scan.authorization_decision_id
        if not authorization_id:
            raise ValueError('Finding is not bound to an authorization decision')
        target = finding.scan.config.get('target', '') if isinstance(finding.scan.config, dict) else ''
        validation = ValidationRun.objects.create(
            user_id=actor_id,
            finding=finding,
            finding_identity_snapshot=finding.id,
            authorization_decision_id=authorization_id,
            target_type='ip',
            target_value=target,
            scope=target,
            profile='quick',
            engines=['nmap'],
            authorized=True,
        )

    result = validate_nmap_finding_e2e.run(str(validation.id))
    validation.refresh_from_db()
    finding.refresh_from_db()

    remediation_id = f"rem-{uuid4().hex[:12]}"
    risk_before = float(finding.risk_score or 0)
    completed_at = _now()
    evidence_id = result.get('evidence_id')

    if result.get('finding_present') is not False or validation.status != ValidationRun.Status.COMPLETED:
        row = {
            'remediation_id': remediation_id, 'finding_id': str(finding.id), 'validation_id': str(validation.id),
            'actor': str(actor_id), 'action_type': 'validated_closure', 'state': 'rejected_by_revalidation',
            'risk_before': risk_before, 'risk_after': risk_before, 'risk_delta': 0.0, 'evidence_id': evidence_id,
            'reason': reason, 'created_at': completed_at, 'completed_at': completed_at,
        }
        _insert_run(row)
        return row

    with transaction.atomic():
        locked = Vulnerability.objects.select_for_update(of=('self',)).get(pk=finding.id)
        old_status = locked.status
        locked.status = Vulnerability.Status.FIXED
        locked.fixed_at = completed_at
        locked.fixed_by_id = actor_id
        locked.validation_status = 'verified'
        locked.risk_score = 0
        locked.save(update_fields=['status', 'fixed_at', 'fixed_by', 'validation_status', 'risk_score', 'updated_at'])
        VulnerabilityStatusHistory.objects.create(
            vulnerability=locked, old_status=old_status, new_status=Vulnerability.Status.FIXED,
            changed_by_id=actor_id, reason=reason,
        )
        AuditLog.objects.create(
            user_id=actor_id,
            action=AuditLog.Action.VULN_FIX_VERIFY,
            result=AuditLog.Result.SUCCESS,
            resource_type='vulnerability',
            resource_id=str(locked.id),
            resource_repr=locked.title[:200],
            changes={'status': [old_status, Vulnerability.Status.FIXED], 'risk_score': [risk_before, 0]},
            metadata={'validation_id': str(validation.id), 'evidence_id': evidence_id, 'remediation_id': remediation_id},
            ip_address='127.0.0.1',
            request_id=validation.id,
        )

    row = {
        'remediation_id': remediation_id, 'finding_id': str(finding.id), 'validation_id': str(validation.id),
        'actor': str(actor_id), 'action_type': 'validated_closure', 'state': 'verified',
        'risk_before': risk_before, 'risk_after': 0.0, 'risk_delta': -risk_before,
        'evidence_id': evidence_id, 'reason': reason, 'created_at': completed_at, 'completed_at': completed_at,
    }
    _insert_run(row)
    return row


def list_runs_for_finding(finding_id: str) -> list[dict]:
    _ensure_schema()
    pool = _db()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT remediation_id FROM remediation_runs WHERE finding_id=%s ORDER BY created_at DESC", (finding_id,))
            ids = [r[0] for r in cur.fetchall()]
    finally:
        pool.putconn(conn)
    return [get_run(remediation_id) for remediation_id in ids]
