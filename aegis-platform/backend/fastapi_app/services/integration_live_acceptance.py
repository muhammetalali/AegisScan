from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from django_project.projects.models import Project
from enterprise.models import (
    ExternalIntegration,
    IntegrationAcceptanceTest,
    IntegrationLiveAcceptance,
    Organization,
    OrganizationMembership,
    TenantProject,
)


_SHA256_RE = re.compile(r'^[a-f0-9]{64}$')


class IntegrationAcceptanceError(ValueError):
    pass


class IntegrationAcceptanceConflict(IntegrationAcceptanceError):
    pass


@dataclass(frozen=True)
class IntegrationAcceptanceTestResult:
    test: IntegrationAcceptanceTest
    replayed: bool


@dataclass(frozen=True)
class IntegrationLiveAcceptanceResult:
    acceptance: IntegrationLiveAcceptance
    generation: int


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def integration_configuration_fingerprint(integration: ExternalIntegration) -> str:
    return _sha({
        'kind': integration.kind,
        'base_url': integration.base_url,
        'secret_ref': integration.secret_ref,
        'config': dict(integration.config or {}),
        'enabled': bool(integration.enabled),
        'configuration_generation': integration.updated_at.isoformat() if integration.updated_at else None,
    })


def _sha256(value: str, *, field: str) -> str:
    normalized = str(value or '').strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise IntegrationAcceptanceError(f'{field} must be a lowercase 64-character SHA-256 hex digest.')
    return normalized


def _parse_future_datetime(value: datetime | str, *, field: str) -> datetime:
    parsed = value
    if not isinstance(parsed, datetime):
        try:
            parsed = datetime.fromisoformat(str(value or '').replace('Z', '+00:00'))
        except (TypeError, ValueError) as exc:
            raise IntegrationAcceptanceError(f'{field} must be a valid timezone-aware datetime.') from exc
    if parsed.tzinfo is None:
        raise IntegrationAcceptanceError(f'{field} must be timezone-aware.')
    if parsed <= timezone.now():
        raise IntegrationAcceptanceError(f'{field} must be in the future.')
    return parsed


def _scope_identity(project_id: str) -> tuple[str, int]:
    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('organization_id', 'id')
        .first()
    )
    if identity is None:
        raise IntegrationAcceptanceError('Project is not bound to an active enterprise tenant.')
    return str(identity['organization_id']), int(identity['id'])


def _locked_scope(*, project_id: str, actor_id: str, integration_id: str):
    organization_id, link_id = _scope_identity(project_id)
    organization = (
        Organization.objects.select_for_update(of=('self',))
        .filter(pk=organization_id, is_active=True)
        .first()
    )
    if organization is None:
        raise IntegrationAcceptanceError('Integration tenant is not active.')
    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=link_id, project_id=project_id, organization=organization)
        .first()
    )
    if link is None:
        raise IntegrationAcceptanceError('Integration project scope changed during execution.')
    membership = OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        user__is_active=True,
        is_active=True,
    ).first()
    project_access = Project.objects.filter(pk=project_id).filter(
        Q(owner_id=actor_id) | Q(members__id=actor_id)
    ).exists()
    if membership is None or not project_access:
        raise PermissionError('Active tenant and project membership are required for integration acceptance operations.')
    integration = (
        ExternalIntegration.objects.select_for_update(of=('self',))
        .filter(pk=integration_id, organization=organization)
        .first()
    )
    if integration is None:
        raise IntegrationAcceptanceError('Integration was not found in the locked tenant scope.')
    return organization, link, integration


def integration_acceptance_generation(*, integration_id: str, project_id: str) -> int:
    tests = IntegrationAcceptanceTest.objects.filter(
        integration_id=integration_id,
        project_id=project_id,
    ).count()
    acceptances = IntegrationLiveAcceptance.objects.filter(
        integration_id=integration_id,
        project_id=project_id,
    ).count()
    return int(tests + acceptances + 1)


def record_integration_acceptance_test(
    *,
    integration_id: str,
    project_id: str,
    actor_id: str,
    outcome: str,
    source_ref: str,
    evidence_sha256: str,
    evidence_summary: dict[str, Any] | None = None,
    test_type: str = 'live_probe',
) -> IntegrationAcceptanceTestResult:
    normalized_outcome = str(outcome or '').strip().lower()
    if normalized_outcome not in {
        IntegrationAcceptanceTest.Outcome.PASSED,
        IntegrationAcceptanceTest.Outcome.FAILED,
    }:
        raise IntegrationAcceptanceError('Integration acceptance test outcome must be passed or failed.')
    normalized_source = str(source_ref or '').strip()
    normalized_type = str(test_type or '').strip()
    if not normalized_source or len(normalized_source) > 255:
        raise IntegrationAcceptanceError('Integration acceptance test source_ref is required and must fit 255 characters.')
    if not normalized_type or len(normalized_type) > 80:
        raise IntegrationAcceptanceError('Integration acceptance test type is required and must fit 80 characters.')
    evidence_hash = _sha256(evidence_sha256, field='evidence_sha256')
    summary = dict(evidence_summary or {})

    with transaction.atomic():
        organization, _link, integration = _locked_scope(
            project_id=str(project_id),
            actor_id=str(actor_id),
            integration_id=str(integration_id),
        )
        existing = IntegrationAcceptanceTest.objects.filter(
            integration=integration,
            project_id=project_id,
            source_ref=normalized_source,
        ).first()
        if existing is not None:
            exact_replay = (
                existing.test_type == normalized_type
                and existing.outcome == normalized_outcome
                and existing.evidence_sha256 == evidence_hash
                and dict(existing.evidence_summary or {}) == summary
                and str(existing.tested_by_id) == str(actor_id)
            )
            if not exact_replay:
                raise IntegrationAcceptanceConflict(
                    'The same integration acceptance test source_ref is already bound to different immutable evidence.'
                )
            return IntegrationAcceptanceTestResult(existing, True)

        configuration_fingerprint = integration_configuration_fingerprint(integration)
        fingerprint = _sha({
            'organization_id': str(organization.id),
            'project_id': str(project_id),
            'integration_id': str(integration.id),
            'configuration_fingerprint': configuration_fingerprint,
            'test_type': normalized_type,
            'outcome': normalized_outcome,
            'source_ref': normalized_source,
            'evidence_sha256': evidence_hash,
            'evidence_summary': summary,
            'tested_by_id': str(actor_id),
        })
        row = IntegrationAcceptanceTest.objects.create(
            organization=organization,
            project_id=project_id,
            integration=integration,
            test_type=normalized_type,
            outcome=normalized_outcome,
            source_ref=normalized_source,
            evidence_sha256=evidence_hash,
            evidence_summary=summary,
            configuration_fingerprint=configuration_fingerprint,
            test_fingerprint=fingerprint,
            tested_by_id=actor_id,
        )
        return IntegrationAcceptanceTestResult(row, False)


def accept_integration_live(
    *,
    integration_id: str,
    project_id: str,
    actor_id: str,
    expected_version: int,
    acceptance_test_id: str,
    vendor_ack: str,
    acceptance_evidence_sha256: str,
    review_at: datetime | str,
    expires_at: datetime | str | None = None,
) -> IntegrationLiveAcceptanceResult:
    normalized_ack = ' '.join(str(vendor_ack or '').split())
    if len(normalized_ack) < 3 or len(normalized_ack) > 500:
        raise IntegrationAcceptanceError('vendor_ack must contain 3-500 normalized characters.')
    evidence_hash = _sha256(acceptance_evidence_sha256, field='acceptance_evidence_sha256')
    review = _parse_future_datetime(review_at, field='review_at')
    expiry = _parse_future_datetime(expires_at, field='expires_at') if expires_at else None
    if expiry is not None and expiry <= review:
        raise IntegrationAcceptanceError('expires_at must be later than review_at when supplied.')

    with transaction.atomic():
        organization, _link, integration = _locked_scope(
            project_id=str(project_id),
            actor_id=str(actor_id),
            integration_id=str(integration_id),
        )
        if not integration.enabled:
            raise IntegrationAcceptanceError('Disabled integrations cannot be accepted for live use.')

        current_generation = integration_acceptance_generation(
            integration_id=str(integration.id),
            project_id=str(project_id),
        )
        if int(expected_version) != current_generation:
            raise IntegrationAcceptanceConflict(
                f'Expected integration acceptance version {expected_version}, current version is {current_generation}.'
            )

        latest_test = (
            IntegrationAcceptanceTest.objects.filter(
                organization=organization,
                project_id=project_id,
                integration=integration,
            )
            .order_by('-tested_at', '-id')
            .first()
        )
        if latest_test is None:
            raise IntegrationAcceptanceError('A durable integration acceptance test is required.')
        if str(latest_test.id) != str(acceptance_test_id):
            raise IntegrationAcceptanceConflict('Live acceptance must bind the latest immutable integration acceptance test.')
        if latest_test.outcome != IntegrationAcceptanceTest.Outcome.PASSED:
            raise IntegrationAcceptanceError('The latest integration acceptance test did not pass.')
        if latest_test.configuration_fingerprint != integration_configuration_fingerprint(integration):
            raise IntegrationAcceptanceConflict(
                'The integration configuration changed after its latest acceptance test; run a new test.'
            )

        if evidence_hash != latest_test.evidence_sha256:
            raise IntegrationAcceptanceError(
                'acceptance_evidence_sha256 must match the latest immutable integration acceptance test evidence.'
            )

        latest_acceptance = (
            IntegrationLiveAcceptance.objects.filter(
                organization=organization,
                project_id=project_id,
                integration=integration,
            )
            .order_by('-accepted_at', '-id')
            .first()
        )
        if latest_acceptance is not None and latest_test.tested_at <= latest_acceptance.accepted_at:
            raise IntegrationAcceptanceConflict(
                'A newer passed integration acceptance test is required before another live acceptance.'
            )

        fingerprint = _sha({
            'organization_id': str(organization.id),
            'project_id': str(project_id),
            'integration_id': str(integration.id),
            'acceptance_test_id': str(latest_test.id),
            'vendor_ack': normalized_ack,
            'acceptance_evidence_sha256': evidence_hash,
            'review_at': review.isoformat(),
            'expires_at': expiry.isoformat() if expiry else None,
            'supersedes_id': str(latest_acceptance.id) if latest_acceptance else None,
            'accepted_by_id': str(actor_id),
            'expected_version': int(expected_version),
        })
        try:
            acceptance = IntegrationLiveAcceptance.objects.create(
                organization=organization,
                project_id=project_id,
                integration=integration,
                acceptance_test=latest_test,
                vendor_ack=normalized_ack,
                acceptance_evidence_sha256=evidence_hash,
                review_at=review,
                expires_at=expiry,
                supersedes=latest_acceptance,
                acceptance_fingerprint=fingerprint,
                accepted_by_id=actor_id,
            )
        except IntegrityError as exc:
            raise IntegrationAcceptanceConflict(
                'The immutable integration acceptance test has already been consumed by a live acceptance.'
            ) from exc

        return IntegrationLiveAcceptanceResult(
            acceptance=acceptance,
            generation=current_generation + 1,
        )
