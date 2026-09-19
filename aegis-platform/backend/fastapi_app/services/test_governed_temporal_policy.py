from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from enterprise.governed_temporal_models import (
    GovernedTemporalEvaluation,
    GovernedTemporalException,
)
from enterprise.models import OrganizationMembership
from fastapi_app.services.governed_action_executor import execute_governed_action
from fastapi_app.services.governed_temporal_policy import (
    GovernedTemporalConflict,
    GovernedTemporalError,
    TemporalEnvelope,
    classify_deadline,
    classify_sla,
    evaluate_governed_temporal_policy,
    issue_temporal_exception,
    revoke_temporal_exception,
    validate_review_deadline,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_finding_governed_actions import _confirmation_request


pytestmark = pytest.mark.django_db(transaction=True)


def _ctx(disposition_fixture):
    client, user, project, asset, authorization, scan, finding, organization, membership = disposition_fixture
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])
    return {
        'client': client,
        'user': user,
        'project': project,
        'asset': asset,
        'authorization': authorization,
        'scan': scan,
        'finding': finding,
        'organization': organization,
        'membership': membership,
    }


def _evaluate(ctx, *, envelope=None, hard_blocks=(), evaluated_at=None, actor=None):
    return evaluate_governed_temporal_policy(
        project_id=str(ctx['project'].id),
        action_id='finding.confirm',
        entity_type='finding',
        entity_id=str(ctx['finding'].id),
        requested_by_id=str(actor.id if actor else ctx['user'].id),
        envelope=envelope,
        hard_blocks=hard_blocks,
        evaluated_at=evaluated_at,
    )


def _issue(ctx, *, kind='exception', key='temporal-exception-1', now=None, **overrides):
    now = now or timezone.now()
    values = {
        'project_id': str(ctx['project'].id),
        'actor_id': str(ctx['user'].id),
        'kind': kind,
        'scope_kind': 'action',
        'action_id': 'finding.confirm',
        'effective_from': now - timedelta(minutes=5),
        'expires_at': now + timedelta(hours=1),
        'reason': 'Governed temporal exception Reality test.',
        'idempotency_key': key,
    }
    values.update(overrides)
    return issue_temporal_exception(**values)


def test_active_evaluation_is_persisted_reproducible_and_immutable(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    as_of = timezone.now()
    envelope = TemporalEnvelope(
        effective_from=as_of - timedelta(minutes=5),
        expires_at=as_of + timedelta(hours=1),
        review_at=as_of + timedelta(minutes=30),
        renewal_ref='renewal-generation-7',
        recurrence={'kind': 'daily', 'generation': 7},
    )
    first = _evaluate(ctx, envelope=envelope, evaluated_at=as_of)
    second = _evaluate(ctx, envelope=envelope, evaluated_at=as_of)
    assert first.allowed is True
    assert first.evaluation.decision == GovernedTemporalEvaluation.Decision.ACTIVE
    assert first.evaluation.recurrence == {'kind': 'daily', 'generation': 7}
    assert first.replayed is False
    assert second.replayed is True
    assert second.evaluation.id == first.evaluation.id
    with pytest.raises(ValidationError):
        GovernedTemporalEvaluation.objects.filter(pk=first.evaluation.id).update(decision='expired')
    with pytest.raises(ValidationError):
        first.evaluation.delete()


def test_not_yet_effective_is_fail_closed_even_with_exception(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    _issue(ctx, now=now)
    result = _evaluate(
        ctx,
        envelope=TemporalEnvelope(
            effective_from=now + timedelta(minutes=10),
            expires_at=now + timedelta(hours=2),
        ),
        evaluated_at=now,
    )
    assert result.allowed is False
    assert result.evaluation.decision == GovernedTemporalEvaluation.Decision.NOT_YET_EFFECTIVE


def test_grace_and_exception_semantics(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    grace = _evaluate(
        ctx,
        envelope=TemporalEnvelope(
            effective_from=now - timedelta(hours=2),
            expires_at=now - timedelta(minutes=5),
            grace_period_seconds=600,
        ),
        evaluated_at=now,
    )
    assert grace.allowed is True
    assert grace.evaluation.decision == GovernedTemporalEvaluation.Decision.GRACE_ACTIVE
    item, _ = _issue(ctx, now=now, key='ordinary-expiry')
    exception = _evaluate(
        ctx,
        envelope=TemporalEnvelope(
            effective_from=now - timedelta(days=1),
            expires_at=now - timedelta(seconds=1),
        ),
        evaluated_at=now,
    )
    assert exception.allowed is True
    assert exception.evaluation.decision == GovernedTemporalEvaluation.Decision.EXCEPTION_ACTIVE
    assert exception.evaluation.exception_id == item.id


def test_waiver_can_cover_review_due_but_not_security_boundaries(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    _issue(ctx, kind='waiver', now=now, key='review-waiver')
    review = _evaluate(
        ctx,
        envelope=TemporalEnvelope(review_at=now - timedelta(seconds=1)),
        evaluated_at=now,
    )
    assert review.allowed is True
    assert review.evaluation.decision == GovernedTemporalEvaluation.Decision.WAIVER_ACTIVE

    for hard_block in (
        'tenant_authority',
        'separation_of_duties',
        'revoked_evidence',
        'expired_authorization',
        'immutable_security_control',
    ):
        result = _evaluate(
            ctx,
            envelope=TemporalEnvelope(
                effective_from=now - timedelta(days=1),
                expires_at=now - timedelta(seconds=1),
            ),
            hard_blocks=[hard_block],
            evaluated_at=now + timedelta(microseconds=1),
        )
        assert result.allowed is False
        assert result.evaluation.decision == GovernedTemporalEvaluation.Decision.HARD_BLOCKED
        assert result.evaluation.exception_id is None
        assert f'HARD_BLOCK:{hard_block}' in result.evaluation.reason_codes


def test_authorization_expiry_is_derived_hard_block_not_waivable(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    _issue(ctx, kind='waiver', now=now, key='auth-expiry-waiver')
    result = _evaluate(
        ctx,
        envelope=TemporalEnvelope(
            effective_from=now - timedelta(days=1),
            expires_at=now - timedelta(seconds=1),
            recurrence={
                'source': 'asset_authorization',
                'authorization_decision_id': str(ctx['authorization'].id),
            },
        ),
        evaluated_at=now,
    )
    assert result.allowed is False
    assert result.evaluation.decision == GovernedTemporalEvaluation.Decision.HARD_BLOCKED
    assert 'HARD_BLOCK:expired_authorization' in result.evaluation.reason_codes
    assert result.evaluation.exception_id is None


def test_revocation_supersession_and_renewal_are_explicit(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    first, _ = _issue(ctx, now=now, key='lineage-first')
    second, _ = _issue(
        ctx,
        now=now + timedelta(seconds=1),
        key='lineage-second',
        supersedes_id=str(first.id),
    )
    assert second.supersedes_id == first.id
    renewal, _ = _issue(
        ctx,
        now=now + timedelta(seconds=2),
        key='lineage-renewal',
        renewal_of_id=str(second.id),
    )
    assert renewal.renewal_of_id == second.id

    revocation, replayed = revoke_temporal_exception(
        exception_id=str(renewal.id),
        actor_id=str(ctx['user'].id),
        reason='Security posture changed; revoke exception.',
        idempotency_key='revoke-lineage-renewal',
    )
    assert replayed is False
    assert revocation.exception_id == renewal.id


def test_action_scope_cannot_bind_entity_id_without_entity_type(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    with pytest.raises(GovernedTemporalError, match='entity_id without entity_type'):
        _issue(
            ctx,
            now=now,
            key='invalid-action-entity-scope',
            entity_id=str(ctx['finding'].id),
        )


def test_lineage_preserves_exact_scope_and_cannot_reuse_revoked_parent(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    first, _ = _issue(ctx, now=now, key='strict-lineage-first')

    with pytest.raises(GovernedTemporalError, match='preserve kind and exact scope semantics'):
        _issue(
            ctx,
            now=now + timedelta(seconds=1),
            key='strict-lineage-wrong-renewal',
            action_id='finding.close',
            renewal_of_id=str(first.id),
        )

    revoke_temporal_exception(
        exception_id=str(first.id),
        actor_id=str(ctx['user'].id),
        reason='Revoke parent before attempted lineage reuse.',
        idempotency_key='strict-lineage-revoke',
    )
    with pytest.raises(GovernedTemporalError, match='revoked'):
        _issue(
            ctx,
            now=now + timedelta(seconds=2),
            key='strict-lineage-revoked-renewal',
            renewal_of_id=str(first.id),
        )


def test_supersession_creation_does_not_self_trigger_reverse_cache_guard(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    first, _ = _issue(ctx, now=now, key='reverse-cache-first')
    second, replayed = _issue(
        ctx,
        now=now + timedelta(seconds=1),
        key='reverse-cache-second',
        supersedes_id=str(first.id),
    )
    assert replayed is False
    assert second.supersedes_id == first.id
    assert first.id != second.id


def test_renewal_lineage_is_single_current_branch(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    first, _ = _issue(ctx, now=now, key='single-renewal-parent')
    renewal, _ = _issue(
        ctx,
        now=now + timedelta(seconds=1),
        key='single-renewal-child',
        renewal_of_id=str(first.id),
    )
    assert renewal.renewal_of_id == first.id
    with pytest.raises(GovernedTemporalConflict, match='already has a current renewal'):
        _issue(
            ctx,
            now=now + timedelta(seconds=2),
            key='single-renewal-branch',
            renewal_of_id=str(first.id),
        )


def test_exception_idempotency_conflict_is_fail_closed(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    now = timezone.now()
    first, replayed = _issue(ctx, now=now, key='idem-temporal')
    assert replayed is False
    replay, replayed = _issue(ctx, now=now, key='idem-temporal')
    assert replayed is True
    assert replay.id == first.id
    with pytest.raises(GovernedTemporalConflict):
        _issue(
            ctx,
            now=now,
            key='idem-temporal',
            reason='Different semantics under same key.',
        )


def test_tenant_and_issuer_authority_are_enforced(disposition_fixture):
    ctx = _ctx(disposition_fixture)
    outsider = type(ctx['user']).objects.create_user(
        email='temporal-outsider@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Temporal',
        last_name='Outsider',
    )
    with pytest.raises(PermissionError):
        _evaluate(ctx, actor=outsider)

    ctx['membership'].role = OrganizationMembership.Role.MANAGER
    ctx['membership'].save(update_fields=['role'])
    with pytest.raises(PermissionError):
        _issue(ctx, key='manager-cannot-waive')


def test_deadline_sla_and_review_helpers_are_central(disposition_fixture):
    _ctx(disposition_fixture)
    now = timezone.now()
    due = classify_deadline(
        due_at=now + timedelta(hours=1),
        now=now,
        warning_window=timedelta(hours=2),
    )
    assert due.state == 'due'
    assert due.escalation_level == 1
    assert classify_deadline(due_at=now - timedelta(seconds=1), now=now).state == 'overdue'
    sla = classify_sla(
        started_at=now - timedelta(minutes=50),
        sla_seconds=3600,
        now=now,
    )
    assert sla.state == 'at_risk'
    assert sla.escalation_level == 1
    assert validate_review_deadline(
        now + timedelta(days=30),
        now=now,
        max_horizon=timedelta(days=365),
    ) > now
    with pytest.raises(GovernedTemporalError):
        validate_review_deadline(now - timedelta(seconds=1), now=now)


def test_governed_finding_confirmation_embeds_temporal_policy(disposition_fixture):
    _ctx(disposition_fixture)
    (
        _owner,
        _project,
        _authorization,
        _finding,
        _organization,
        _owner_membership,
        _confirmer,
        _validation,
        _evidence,
        kwargs,
    ) = _confirmation_request(disposition_fixture)
    result = execute_governed_action(**kwargs)
    temporal = result.execution.result_payload['temporal_policy']
    assert temporal['allowed'] is True
    assert temporal['decision'] == GovernedTemporalEvaluation.Decision.ACTIVE
    assert temporal['policy_version'] == 'agom-temporal.v1'
    assert len(temporal['evaluation_fingerprint']) == 64
    evaluation = GovernedTemporalEvaluation.objects.get(pk=temporal['evaluation_id'])
    assert evaluation.action_id == 'finding.confirm'
    assert evaluation.entity_id == kwargs['entity_id']
