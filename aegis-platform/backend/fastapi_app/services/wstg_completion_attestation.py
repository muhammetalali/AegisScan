from __future__ import annotations

import hashlib
import json
from typing import Any

from django.db import transaction
from django.db.models import Q

from django_project.evidence.models import Evidence
from enterprise.models import WSTGMethodologyAttestation
from django_project.projects.models import Project
from django_project.scans.models import Scan
from enterprise.models import OrganizationMembership, TenantProject

from .evidence_qualification import EvidenceQualificationPolicy, qualify_evidence
from .wstg_catalog import WSTGCatalog
from .wstg_completion_policy import build_wstg_completion_policy
from .wstg_reporting import _trusted_lineage


class WSTGAttestationError(ValueError):
    pass


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')
    ).hexdigest()


def _project_for_actor(project_id: str, actor_id: str) -> Project:
    project = Project.objects.filter(
        Q(id=project_id) & (Q(owner_id=actor_id) | Q(members__id=actor_id))
    ).distinct().first()
    if project is None:
        raise WSTGAttestationError('Project not found or actor is not a member.')
    link = TenantProject.objects.filter(project=project, organization__is_active=True).first()
    if link is None:
        raise WSTGAttestationError('Project is not bound to an active enterprise tenant.')
    role = (
        OrganizationMembership.objects.filter(
            organization_id=link.organization_id,
            user_id=actor_id,
            is_active=True,
            role__in=[
                OrganizationMembership.Role.OWNER,
                OrganizationMembership.Role.ADMIN,
                OrganizationMembership.Role.MANAGER,
                OrganizationMembership.Role.ANALYST,
            ],
        )
        .values_list('role', flat=True)
        .first()
    )
    if role is None:
        raise WSTGAttestationError('Actor lacks an active governed analyst-or-higher tenant role.')
    return project


def _lineage_supports_test(evidence: Evidence, wstg_id: str) -> bool:
    metadata = evidence.metadata if isinstance(evidence.metadata, dict) else {}
    lineage = _trusted_lineage(metadata.get('wstg_lineage'), expected_source=evidence.source)
    if lineage is None:
        return False
    return any(item.get('wstg_id') == wstg_id for item in lineage.get('tests', []))


def create_wstg_methodology_attestation(
    *,
    project_id: str,
    actor_id: str,
    wstg_id: str,
    evidence_ids: list[str],
    rationale: str,
    decision: str = 'completed',
    scan_id: str | None = None,
) -> dict[str, Any]:
    project = _project_for_actor(str(project_id), str(actor_id))
    test = WSTGCatalog().resolve(str(wstg_id))
    policy = build_wstg_completion_policy()
    row = next(item for item in policy['rows'] if item['wstg_id'] == test.id)
    mode = row['completion_mode']

    expected_decision = (
        WSTGMethodologyAttestation.Decision.NOT_APPLICABLE
        if test.classification == 'CONDITIONAL_NA'
        else WSTGMethodologyAttestation.Decision.COMPLETED
    )
    if decision != expected_decision:
        raise WSTGAttestationError(
            f'{test.id} requires decision={expected_decision}; methodology completion never represents pass/fail.'
        )
    reason = str(rationale or '').strip()
    if len(reason) < 12 or len(reason) > 4000:
        raise WSTGAttestationError('A governed rationale between 12 and 4000 characters is required.')

    normalized_evidence = sorted({str(item).strip() for item in evidence_ids if str(item).strip()})
    if not normalized_evidence:
        raise WSTGAttestationError('At least one evidence record is required for a WSTG methodology attestation.')

    scan = None
    if scan_id:
        scan = Scan.objects.filter(pk=scan_id, project=project).first()
        if scan is None:
            raise WSTGAttestationError('Attestation scan does not belong to the project.')

    rows = list(
        Evidence.objects.select_related('scan', 'asset', 'finding')
        .filter(pk__in=normalized_evidence)
        .filter(Q(scan__project=project) | Q(asset__project=project) | Q(finding__project=project))
        .distinct()
    )
    if len(rows) != len(normalized_evidence):
        raise WSTGAttestationError('One or more evidence records are missing or outside the project.')
    if scan is not None and any(str(item.scan_id or '') != str(scan.id) for item in rows):
        raise WSTGAttestationError('Scan-scoped attestation evidence must belong to the exact scan.')
    if test.classification in {'AUTO_EXISTING', 'ASSISTED_EXISTING', 'GAP_NATIVE_SMALL'}:
        unsupported = [str(item.id) for item in rows if not _lineage_supports_test(item, test.id)]
        if unsupported:
            raise WSTGAttestationError(
                f'Evidence does not contain trusted canonical WSTG lineage for {test.id}: {unsupported}'
            )

    qualification = qualify_evidence(
        project_id=str(project.id),
        evidence_ids=normalized_evidence,
        subject_type='wstg_test',
        subject_id=test.id,
        requested_by_id=str(actor_id),
        policy=EvidenceQualificationPolicy(
            policy_version='wstg-completion-evidence.v1',
            min_count=1,
            require_subject=False,
            require_target=False,
            require_authorization=False,
            require_execution=False,
            require_producer=True,
        ),
    )
    if not qualification.qualified:
        raise WSTGAttestationError(
            'WSTG completion evidence failed qualification: '
            + ','.join(qualification.evaluation.reason_codes)
        )

    material = {
        'policy_version': 'wstg-completion.v1',
        'project_id': str(project.id),
        'scan_id': str(scan.id) if scan else None,
        'wstg_id': test.id,
        'classification': test.classification,
        'completion_mode': mode,
        'decision': decision,
        'evidence_ids': normalized_evidence,
        'evidence_qualification_fingerprint': qualification.evaluation.evaluation_fingerprint,
        'actor_id': str(actor_id),
        'rationale': reason,
    }
    fingerprint = _sha(material)

    with transaction.atomic():
        attestation, created = WSTGMethodologyAttestation.objects.get_or_create(
            request_fingerprint=fingerprint,
            defaults={
                'project': project,
                'scan': scan,
                'created_by_id': actor_id,
                'evidence_qualification': qualification.evaluation,
                'wstg_id': test.id,
                'classification': test.classification,
                'completion_mode': mode,
                'decision': decision,
                'evidence_ids': normalized_evidence,
                'rationale': reason,
                'policy_version': 'wstg-completion.v1',
            },
        )
    return {
        'id': str(attestation.id),
        'project_id': str(attestation.project_id),
        'scan_id': str(attestation.scan_id) if attestation.scan_id else None,
        'wstg_id': attestation.wstg_id,
        'classification': attestation.classification,
        'completion_mode': attestation.completion_mode,
        'decision': attestation.decision,
        'evidence_ids': list(attestation.evidence_ids),
        'evidence_qualification_id': str(attestation.evidence_qualification_id),
        'evidence_qualification_fingerprint': attestation.evidence_qualification.evaluation_fingerprint,
        'request_fingerprint': attestation.request_fingerprint,
        'created_by_id': str(attestation.created_by_id),
        'created_at': attestation.created_at,
        'replayed': not created,
    }
