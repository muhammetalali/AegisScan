from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any, Iterable

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from django_project.assets.models import AssetAuthorization
from django_project.evidence.models import Evidence
from enterprise.governed_action_models import EvidenceQualificationEvaluation
from enterprise.models import TenantProject


DEFAULT_POLICY_VERSION = 'agom-evidence-qualification.v1'


class EvidenceQualificationError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceQualificationPolicy:
    policy_version: str = DEFAULT_POLICY_VERSION
    min_count: int = 1
    evidence_types: tuple[str, ...] = ()
    max_age_seconds: int | None = None
    min_confidence: float | None = None
    source_capabilities: tuple[str, ...] = ()
    require_subject: bool = True
    require_target: bool = False
    require_authorization: bool = False
    require_execution: bool = False
    require_producer: bool = True
    require_verifier: bool = False

    def snapshot(self) -> dict[str, Any]:
        data = asdict(self)
        data['evidence_types'] = list(self.evidence_types)
        data['source_capabilities'] = list(self.source_capabilities)
        return data


@dataclass(frozen=True)
class EvidenceQualificationResult:
    evaluation: EvidenceQualificationEvaluation
    replayed: bool

    @property
    def qualified(self) -> bool:
        return bool(self.evaluation.qualified)


_PRIORITY = (
    EvidenceQualificationEvaluation.Decision.WRONG_TENANT,
    EvidenceQualificationEvaluation.Decision.WRONG_PROJECT,
    EvidenceQualificationEvaluation.Decision.WRONG_SUBJECT,
    EvidenceQualificationEvaluation.Decision.WRONG_TARGET,
    EvidenceQualificationEvaluation.Decision.WRONG_EXECUTION,
    EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED,
    EvidenceQualificationEvaluation.Decision.INTEGRITY_MISMATCH,
    EvidenceQualificationEvaluation.Decision.REVOKED,
    EvidenceQualificationEvaluation.Decision.EXPIRED,
    EvidenceQualificationEvaluation.Decision.SUPERSEDED,
    EvidenceQualificationEvaluation.Decision.CONTRADICTED,
    EvidenceQualificationEvaluation.Decision.STALE,
    EvidenceQualificationEvaluation.Decision.REPLAYED_EVIDENCE,
    EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE,
    EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any) -> str:
    return str(value or '').strip()


def _metadata(evidence: Evidence) -> dict[str, Any]:
    return evidence.metadata if isinstance(evidence.metadata, dict) else {}


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _text(value).lower() in {'1', 'true', 'yes', 'on', 'revoked', 'contradicted'}


def _timestamp(value: Any) -> datetime | None:
    if value in (None, ''):
        return None
    parsed = value if isinstance(value, datetime) else parse_datetime(_text(value))
    if parsed is None:
        return None
    return timezone.make_aware(parsed, dt_timezone.utc) if timezone.is_naive(parsed) else parsed


def _reason(reasons: list[dict[str, str]], code: str, detail: str, evidence_id: str = '') -> None:
    item = {'code': str(code), 'detail': str(detail), 'evidence_id': _text(evidence_id)}
    if item not in reasons:
        reasons.append(item)


def _project_ids(evidence: Evidence) -> set[str]:
    values: set[str] = set()
    if evidence.scan_id and evidence.scan is not None:
        values.add(_text(evidence.scan.project_id))
    if evidence.asset_id and evidence.asset is not None:
        values.add(_text(evidence.asset.project_id))
    if evidence.finding_id and evidence.finding is not None:
        values.add(_text(evidence.finding.project_id))
    values.discard('')
    return values


def _asset_ids(evidence: Evidence) -> set[str]:
    values = {
        _text(evidence.asset_id),
        _text(getattr(getattr(evidence, 'scan', None), 'asset_id', '')),
        _text(getattr(getattr(evidence, 'finding', None), 'asset_id', '')),
    }
    values.discard('')
    return values


def _targets(evidence: Evidence) -> set[str]:
    metadata = _metadata(evidence)
    values = {_text(metadata.get(key)) for key in ('target', 'target_value', 'authorization_target')}
    scan = getattr(evidence, 'scan', None)
    if scan is not None:
        for source in (
            scan.config if isinstance(scan.config, dict) else {},
            scan.execution_contract if isinstance(scan.execution_contract, dict) else {},
        ):
            values.update(_text(source.get(key)) for key in ('target', 'host', 'ip', 'url', 'domain', 'cidr', 'repo_url', 'path'))
    asset = getattr(evidence, 'asset', None)
    if asset is not None:
        config = asset.configuration if isinstance(asset.configuration, dict) else {}
        values.update(_text(config.get(key)) for key in ('target', 'host', 'ip', 'url', 'domain', 'cidr', 'repo_url', 'path'))
    values.discard('')
    return values


def _authorization_refs(evidence: Evidence) -> set[str]:
    metadata = _metadata(evidence)
    values = {_text(metadata.get('authorization_decision_id')), _text(metadata.get('authorization_ref'))}
    scan = getattr(evidence, 'scan', None)
    if scan is not None:
        values.add(_text(scan.authorization_decision_id))
    finding_scan = getattr(getattr(evidence, 'finding', None), 'scan', None)
    if finding_scan is not None:
        values.add(_text(finding_scan.authorization_decision_id))
    values.discard('')
    return values


def _execution_refs(evidence: Evidence) -> set[str]:
    metadata = _metadata(evidence)
    values = {
        _text(metadata.get('execution_ref')),
        _text(metadata.get('execution_id')),
        _text(metadata.get('validation_run_id')),
        _text(metadata.get('validation_id')),
    }
    scan = getattr(evidence, 'scan', None)
    if scan is not None:
        values.add(_text(scan.execution_correlation_id))
    values.discard('')
    return values


def _subject_matches(evidence: Evidence, subject_type: str, subject_id: str) -> bool:
    normalized = _text(subject_type).lower()
    if normalized in {'finding', 'vulnerability'}:
        return _text(evidence.finding_id) == subject_id
    if normalized == 'asset':
        return subject_id in _asset_ids(evidence)
    if normalized == 'scan':
        return _text(evidence.scan_id) == subject_id
    metadata = _metadata(evidence)
    return (
        _text(metadata.get('subject_type')).lower() == normalized
        and _text(metadata.get('subject_id') or metadata.get('subject_ref')) == subject_id
    )


def _producer(evidence: Evidence) -> str:
    metadata = _metadata(evidence)
    return _text(evidence.collected_by_id or metadata.get('producer_id') or metadata.get('producer_ref') or metadata.get('producer'))


def _verifier(evidence: Evidence) -> str:
    metadata = _metadata(evidence)
    return _text(metadata.get('verifier_id') or metadata.get('verifier_ref') or metadata.get('verifier'))


def _capability(evidence: Evidence) -> str:
    metadata = _metadata(evidence)
    return _text(metadata.get('source_capability') or metadata.get('capability_id') or metadata.get('capability'))


def _confidence(evidence: Evidence) -> float | None:
    value = _metadata(evidence).get('confidence')
    try:
        return None if value in (None, '') else float(value)
    except (TypeError, ValueError):
        return None


def _validate_authorization(
    evidence: Evidence,
    authorization_ref: str,
    target: str,
    evaluated_at: datetime,
    reasons: list[dict[str, str]],
) -> None:
    evidence_id = str(evidence.id)
    refs = _authorization_refs(evidence)
    effective_ref = authorization_ref
    if not effective_ref:
        if len(refs) == 1:
            effective_ref = next(iter(refs))
        else:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Evidence does not resolve to exactly one authorization decision.', evidence_id)
            return
    if effective_ref not in refs:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Evidence authorization lineage does not match the governed request.', evidence_id)
        return
    decision = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .select_related('asset')
        .filter(pk=effective_ref)
        .first()
    )
    if decision is None or decision.asset_id is None:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Authorization decision is missing or not bound to a persisted asset.', evidence_id)
        return
    latest = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(asset_id=decision.asset_id)
        .order_by('-created_at', '-id')
        .first()
    )
    if decision.asset_identity_snapshot != decision.asset_id:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Authorization asset identity snapshot no longer matches the asset.', evidence_id)
    if latest is None or latest.id != decision.id:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Authorization decision is no longer current.', evidence_id)
    if decision.authorized is not True or decision.valid_from > evaluated_at or (decision.expires_at and decision.expires_at <= evaluated_at):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Authorization decision is not valid at qualification time.', evidence_id)
    if _text(decision.asset_id) not in _asset_ids(evidence):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.NOT_AUTHORIZED, 'Evidence asset lineage does not match the authorization asset.', evidence_id)
    if target and _text(decision.target_snapshot) != target:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.WRONG_TARGET, 'Authorization target snapshot does not match the governed target.', evidence_id)


def _state_reasons(evidence: Evidence, policy: EvidenceQualificationPolicy, evaluated_at: datetime, reasons: list[dict[str, str]]) -> None:
    evidence_id = str(evidence.id)
    metadata = _metadata(evidence)
    computed = hashlib.sha256((evidence.raw_output or '').encode('utf-8', errors='replace')).hexdigest()
    if not evidence.sha256 or computed != evidence.sha256:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.INTEGRITY_MISMATCH, 'Persisted evidence SHA-256 does not match raw output.', evidence_id)
    if policy.evidence_types and evidence.evidence_type not in set(policy.evidence_types):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE, 'Evidence type is not admitted by policy.', evidence_id)
    if not _text(evidence.source) or not evidence.collected_at or not evidence.sha256:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Source, collection timestamp, and integrity digest are required.', evidence_id)
    if policy.require_producer and not _producer(evidence):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Producer lineage is required.', evidence_id)
    if policy.require_verifier and not _verifier(evidence):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Verifier lineage is required.', evidence_id)
    if policy.max_age_seconds is not None and evidence.collected_at and evaluated_at - evidence.collected_at > timedelta(seconds=policy.max_age_seconds):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.STALE, 'Evidence exceeds the maximum policy age.', evidence_id)
    expires_at_raw = metadata.get('expires_at') or metadata.get('evidence_expires_at')
    if expires_at_raw:
        expires_at = _timestamp(expires_at_raw)
        if expires_at is None:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Evidence expiry metadata is not parseable.', evidence_id)
        elif expires_at <= evaluated_at:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.EXPIRED, 'Evidence lifecycle has expired.', evidence_id)
    if _truthy(metadata.get('revoked')) or metadata.get('revoked_at'):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.REVOKED, 'Evidence has been revoked.', evidence_id)
    if _text(metadata.get('superseded_by')):
        _reason(reasons, EvidenceQualificationEvaluation.Decision.SUPERSEDED, 'Evidence has been superseded.', evidence_id)
    contradiction = metadata.get('contradicted') or metadata.get('contradiction') or metadata.get('contradiction_state')
    if _truthy(contradiction) or _text(contradiction).lower() in {'conflict', 'conflicting'}:
        _reason(reasons, EvidenceQualificationEvaluation.Decision.CONTRADICTED, 'Evidence is contradicted by authoritative lineage.', evidence_id)
    confidence = _confidence(evidence)
    if policy.min_confidence is not None:
        if confidence is None:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Confidence is required by policy.', evidence_id)
        elif confidence < policy.min_confidence:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE, 'Evidence confidence is below the policy minimum.', evidence_id)
    if policy.source_capabilities:
        source_capability = _capability(evidence)
        if not source_capability:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Source capability lineage is required.', evidence_id)
        elif source_capability not in set(policy.source_capabilities):
            _reason(reasons, EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE, 'Source capability is not admitted by policy.', evidence_id)


def _decision(reason_codes: Iterable[str]) -> str:
    values = set(reason_codes)
    for candidate in _PRIORITY:
        if candidate in values:
            return candidate
    return EvidenceQualificationEvaluation.Decision.QUALIFIED


def qualify_evidence(
    *,
    project_id: str,
    evidence_ids: Iterable[str],
    subject_type: str,
    subject_id: str,
    target: str = '',
    authorization_ref: str = '',
    execution_ref: str = '',
    organization_id: str = '',
    requested_by_id: str | None = None,
    policy: EvidenceQualificationPolicy | None = None,
    evaluated_at: datetime | None = None,
) -> EvidenceQualificationResult:
    policy = policy or EvidenceQualificationPolicy()
    if policy.min_count < 1:
        raise EvidenceQualificationError('Evidence qualification min_count must be at least one.')
    project_id = _text(project_id)
    subject_type = _text(subject_type).lower()
    subject_id = _text(subject_id)
    target = _text(target)
    authorization_ref = _text(authorization_ref)
    execution_ref = _text(execution_ref)
    organization_id = _text(organization_id)
    requested_ids = sorted(_text(value) for value in evidence_ids if _text(value))
    unique_ids = sorted(set(requested_ids))
    as_of = evaluated_at or timezone.now()
    if timezone.is_naive(as_of):
        as_of = timezone.make_aware(as_of, dt_timezone.utc)
    if not project_id or not subject_type or not subject_id:
        raise EvidenceQualificationError('project_id, subject_type, and subject_id are required.')

    with transaction.atomic():
        link = (
            TenantProject.objects.select_for_update(of=('self',))
            .select_related('organization', 'project')
            .filter(project_id=project_id, organization__is_active=True)
            .first()
        )
        if link is None:
            raise EvidenceQualificationError('Project is not bound to an active enterprise tenant.')
        if organization_id and organization_id != str(link.organization_id):
            raise EvidenceQualificationError('Organization does not own the requested project.')
        rows = list(
            Evidence.objects.select_for_update(of=('self',))
            .select_related(
                'scan', 'scan__asset', 'scan__authorization_decision',
                'asset', 'finding', 'finding__asset', 'finding__scan',
                'finding__scan__authorization_decision', 'collected_by',
            )
            .filter(pk__in=unique_ids)
        )
        by_id = {str(item.id): item for item in rows}
        reasons: list[dict[str, str]] = []
        if len(requested_ids) != len(unique_ids):
            _reason(reasons, EvidenceQualificationEvaluation.Decision.REPLAYED_EVIDENCE, 'Evidence set contains duplicate references.')
        for missing_id in sorted(set(unique_ids) - set(by_id)):
            _reason(reasons, EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE, 'Requested evidence record does not exist.', missing_id)
        if len(rows) < policy.min_count:
            _reason(reasons, EvidenceQualificationEvaluation.Decision.INSUFFICIENT_EVIDENCE, f'Policy requires at least {policy.min_count} evidence record(s).')

        snapshots: list[dict[str, Any]] = []
        for evidence_id in unique_ids:
            evidence = by_id.get(evidence_id)
            if evidence is None:
                snapshots.append({'evidence_id': evidence_id, 'missing': True})
                continue
            projects = _project_ids(evidence)
            targets = _targets(evidence)
            authorization_refs = _authorization_refs(evidence)
            execution_refs = _execution_refs(evidence)
            metadata = _metadata(evidence)
            computed_sha = hashlib.sha256((evidence.raw_output or '').encode('utf-8', errors='replace')).hexdigest()

            if not projects:
                _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Evidence has no project lineage.', evidence_id)
            for evidence_project in sorted(projects):
                if evidence_project == project_id:
                    continue
                other = TenantProject.objects.select_related('organization').filter(project_id=evidence_project).first()
                code = (
                    EvidenceQualificationEvaluation.Decision.WRONG_TENANT
                    if other is not None and other.organization_id != link.organization_id
                    else EvidenceQualificationEvaluation.Decision.WRONG_PROJECT
                )
                _reason(reasons, code, 'Evidence belongs to a different tenant/project scope.', evidence_id)
            if policy.require_subject and not _subject_matches(evidence, subject_type, subject_id):
                _reason(reasons, EvidenceQualificationEvaluation.Decision.WRONG_SUBJECT, 'Evidence subject does not match the governed subject.', evidence_id)
            if policy.require_target:
                if not target:
                    _reason(reasons, EvidenceQualificationEvaluation.Decision.WRONG_TARGET, 'Governed request is missing the required target.', evidence_id)
                elif not targets:
                    _reason(reasons, EvidenceQualificationEvaluation.Decision.MISSING_PROVENANCE, 'Evidence has no target lineage.', evidence_id)
                elif target not in targets:
                    _reason(reasons, EvidenceQualificationEvaluation.Decision.WRONG_TARGET, 'Evidence target does not match the governed target.', evidence_id)
            if policy.require_execution:
                if not execution_ref or execution_ref not in execution_refs:
                    _reason(reasons, EvidenceQualificationEvaluation.Decision.WRONG_EXECUTION, 'Evidence execution lineage does not match the governed execution.', evidence_id)
            if policy.require_authorization:
                _validate_authorization(evidence, authorization_ref, target, as_of, reasons)
            _state_reasons(evidence, policy, as_of, reasons)

            snapshots.append({
                'evidence_id': evidence_id,
                'evidence_type': evidence.evidence_type,
                'source': evidence.source,
                'stored_sha256': evidence.sha256,
                'computed_sha256': computed_sha,
                'project_ids': sorted(projects),
                'asset_ids': sorted(_asset_ids(evidence)),
                'finding_id': _text(evidence.finding_id),
                'scan_id': _text(evidence.scan_id),
                'targets': sorted(targets),
                'authorization_refs': sorted(authorization_refs),
                'execution_refs': sorted(execution_refs),
                'producer_ref': _producer(evidence),
                'verifier_ref': _verifier(evidence),
                'source_capability': _capability(evidence),
                'confidence': _confidence(evidence),
                'generation': metadata.get('generation'),
                'collected_at': evidence.collected_at.isoformat() if evidence.collected_at else None,
                'expires_at': _text(metadata.get('expires_at') or metadata.get('evidence_expires_at')),
                'revoked_at': _text(metadata.get('revoked_at')),
                'superseded_by': _text(metadata.get('superseded_by')),
                'contradiction_state': _text(metadata.get('contradiction_state') or metadata.get('contradiction')),
            })

        reason_codes = list(dict.fromkeys(item['code'] for item in reasons))
        decision = _decision(reason_codes)
        qualified = decision == EvidenceQualificationEvaluation.Decision.QUALIFIED
        policy_snapshot = policy.snapshot()
        context = {
            'organization_id': str(link.organization_id),
            'project_id': project_id,
            'subject_type': subject_type,
            'subject_id': subject_id,
            'target': target,
            'authorization_ref': authorization_ref,
            'execution_ref': execution_ref,
            'requested_by_id': _text(requested_by_id),
            'evaluated_at': as_of.isoformat(),
        }
        evidence_set_hash = _sha(snapshots)
        fingerprint = _sha({
            'policy': policy_snapshot,
            'context': context,
            'requested_evidence_ids': requested_ids,
            'evidence_snapshot': snapshots,
        })
        evaluation, created = EvidenceQualificationEvaluation.objects.get_or_create(
            evaluation_fingerprint=fingerprint,
            defaults={
                'organization': link.organization,
                'project': link.project,
                'requested_by_id': requested_by_id or None,
                'subject_type': subject_type,
                'subject_id': subject_id,
                'target': target,
                'authorization_ref': authorization_ref,
                'execution_ref': execution_ref,
                'policy_version': policy.policy_version,
                'policy_snapshot': policy_snapshot,
                'requested_evidence_ids': requested_ids,
                'evidence_snapshot': snapshots,
                'evidence_set_hash': evidence_set_hash,
                'decision': decision,
                'qualified': qualified,
                'reason_codes': reason_codes,
                'reasons': reasons,
                'evaluation_context': context,
                'evaluated_at': as_of,
            },
        )
        return EvidenceQualificationResult(evaluation=evaluation, replayed=not created)
