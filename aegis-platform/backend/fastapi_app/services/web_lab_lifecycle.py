from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta
from uuid import UUID

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from django_project.assets.models import Asset
from enterprise.models import OrganizationMembership, TenantProject
from enterprise.web_lab_models import WebLabInstance, WebLabLifecycleEvent

from .burp_mcp_gateway import _project_access
from .authorization_guard import current_asset_authorization
from .lab_verification import record_runtime_inspection
from .web_labs_preparation import lab_definition


POLICY = 'aegis.web-lab-lifecycle.v1'
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 14_400
CONTAINER_NAME = re.compile(r'^aegis-web-lab-[0-9a-f]{12}$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
IMAGE_ID = re.compile(r'^sha256:[0-9a-f]{64}$')
IDEMPOTENCY = re.compile(r'^[A-Za-z0-9._:-]{1,128}$')
FAILURE_CODE = re.compile(r'^[a-z0-9][a-z0-9_.:-]{0,79}$')


class WebLabLifecycleError(ValueError):
    pass


class WebLabLifecycleAccessError(WebLabLifecycleError):
    pass


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _digest(value) -> str:
    raw = value if isinstance(value, str) else _canonical(value)
    return hashlib.sha256(raw.encode()).hexdigest()


def _uuid(value, field: str) -> str:
    try:
        canonical = str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WebLabLifecycleError(f'{field} must be a canonical UUID') from exc
    if canonical != str(value):
        raise WebLabLifecycleError(f'{field} must be a canonical UUID')
    return canonical


def _idempotency(value: str) -> str:
    if not isinstance(value, str) or not IDEMPOTENCY.fullmatch(value):
        raise WebLabLifecycleError('Invalid lifecycle idempotency key')
    return value


def _management_scope(*, actor_id: str, asset_id: str):
    actor = get_user_model().objects.filter(pk=actor_id, is_active=True).first()
    asset = Asset.objects.select_related('project').filter(pk=asset_id, is_active=True).first()
    if not actor or not asset or not _project_access(asset.project, str(actor_id)):
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    link = TenantProject.objects.filter(project=asset.project, organization__is_active=True).first()
    if (not link or not OrganizationMembership.objects.filter(
            organization=link.organization, user=actor, is_active=True,
            role__in=[OrganizationMembership.Role.OWNER, OrganizationMembership.Role.MANAGER]).exists()):
        raise WebLabLifecycleAccessError('Web Lab lifecycle requires current tenant management authority.')
    return actor, link.organization, asset


def _read_scope(*, actor_id: str, project_id: str):
    actor = get_user_model().objects.filter(pk=actor_id, is_active=True).first()
    link = TenantProject.objects.select_related('project').filter(
        project_id=project_id, organization__is_active=True).first()
    if not actor or not link or not _project_access(link.project, str(actor_id)):
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    return actor, link


def _effective_status(instance: WebLabInstance) -> str:
    if instance.status == WebLabInstance.Status.READY and timezone.now() >= instance.expires_at:
        return WebLabInstance.Status.EXPIRED
    return instance.status


def public_instance_projection(instance: WebLabInstance) -> dict:
    return {
        'lifecycle_ref': str(instance.id),
        'project_ref': str(instance.project_id),
        'asset_ref': str(instance.asset_id),
        'lab_ref': instance.definition_id,
        'fixture_revision': instance.fixture_revision,
        'variant': instance.variant,
        'generation': instance.generation,
        'instance_ref': str(instance.instance_ref),
        'status': instance.status,
        'effective_status': _effective_status(instance),
        'runtime_evidence_ref': str(instance.runtime_evidence_id),
        'supersedes_ref': str(instance.supersedes_id) if instance.supersedes_id else None,
        'expires_at': instance.expires_at.isoformat(),
        'created_at': instance.created_at.isoformat(),
        'cleaned_at': instance.cleaned_at.isoformat() if instance.cleaned_at else None,
    }


def host_instance_projection(instance: WebLabInstance) -> dict:
    return {
        **public_instance_projection(instance),
        'image_id': instance.image_id,
        'container_id': instance.container_id,
        'container_name': instance.container_name,
        'target': instance.target,
        'version': instance.version,
    }


def _fingerprint(operation: str, payload: dict) -> str:
    return _digest({'policy': POLICY, 'operation': operation, **payload})


def _existing_event(*, organization_id, idempotency_key: str, fingerprint: str):
    event = WebLabLifecycleEvent.objects.select_related('instance').filter(
        organization_id=organization_id, idempotency_key=idempotency_key).first()
    if not event:
        return None
    if event.request_fingerprint != fingerprint:
        raise WebLabLifecycleError('Lifecycle idempotency key was already used for another request.')
    return host_instance_projection(event.instance)


def _append_event(*, instance: WebLabInstance, actor_id: str, event_type: str,
                  idempotency_key: str, fingerprint: str, before_status: str,
                  details: dict, runtime_evidence_id=None):
    previous = instance.lifecycle_events.order_by('-sequence').first()
    previous_hash = previous.entry_hash if previous else ''
    body = {
        'policy': POLICY,
        'instance_ref': str(instance.id),
        'sequence': instance.version,
        'event_type': event_type,
        'actor_ref': str(actor_id),
        'request_fingerprint': fingerprint,
        'before_status': before_status,
        'after_status': instance.status,
        'generation': instance.generation,
        'runtime_evidence_ref': str(runtime_evidence_id) if runtime_evidence_id else None,
        'details': details,
        'previous_hash': previous_hash,
    }
    return WebLabLifecycleEvent.objects.create(
        instance=instance, organization=instance.organization, project=instance.project,
        actor_id=actor_id, sequence=instance.version, event_type=event_type,
        idempotency_key=idempotency_key, request_fingerprint=fingerprint,
        before_status=before_status, after_status=instance.status,
        generation=instance.generation, runtime_evidence_id=runtime_evidence_id,
        details=details, previous_hash=previous_hash, entry_hash=_digest(body),
    )


def verify_lifecycle_chain(*, actor_id: str, instance_id: str) -> dict:
    instance_id = _uuid(instance_id, 'instance_id')
    instance = WebLabInstance.objects.select_related('project').filter(pk=instance_id).first()
    if not instance:
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    _read_scope(actor_id=actor_id, project_id=str(instance.project_id))
    events = list(instance.lifecycle_events.order_by('sequence', 'occurred_at', 'id'))
    if not events or len(events) != instance.version:
        raise WebLabLifecycleError('Web Lab lifecycle event count does not match the state version.')

    previous_hash = ''
    for expected_sequence, event in enumerate(events, start=1):
        if (event.sequence != expected_sequence
                or event.instance_id != instance.id
                or event.organization_id != instance.organization_id
                or event.project_id != instance.project_id
                or event.generation != instance.generation
                or event.previous_hash != previous_hash):
            raise WebLabLifecycleError('Web Lab lifecycle event lineage is inconsistent.')
        body = {
            'policy': POLICY,
            'instance_ref': str(instance.id),
            'sequence': event.sequence,
            'event_type': event.event_type,
            'actor_ref': str(event.actor_id),
            'request_fingerprint': event.request_fingerprint,
            'before_status': event.before_status,
            'after_status': event.after_status,
            'generation': event.generation,
            'runtime_evidence_ref': str(event.runtime_evidence_id) if event.runtime_evidence_id else None,
            'details': event.details,
            'previous_hash': event.previous_hash,
        }
        if event.entry_hash != _digest(body):
            raise WebLabLifecycleError('Web Lab lifecycle event hash verification failed.')
        previous_hash = event.entry_hash
    if events[-1].after_status != instance.status or events[-1].sequence != instance.version:
        raise WebLabLifecycleError('Web Lab lifecycle head does not match the current state projection.')
    return {
        'status': 'pass', 'lifecycle_ref': str(instance.id), 'version': instance.version,
        'event_count': len(events), 'head_hash': previous_hash,
    }


def due_web_lab_instances(*, actor_id: str, project_id: str, limit: int = 100) -> list[dict]:
    project_id = _uuid(project_id, 'project_id')
    _read_scope(actor_id=actor_id, project_id=project_id)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise WebLabLifecycleError('Invalid lifecycle due limit.')
    rows = WebLabInstance.objects.filter(
        project_id=project_id, status=WebLabInstance.Status.READY,
        expires_at__lte=timezone.now(),
    ).order_by('expires_at', 'id')[:limit]
    return [host_instance_projection(row) for row in rows]


def register_provisioned_instance(*, actor_id: str, asset_id: str, lab_definition_id: str,
                                  inspection: dict, container_name: str, ttl_seconds: int,
                                  idempotency_key: str, supersedes_instance_id: str | None = None) -> dict:
    """Trusted-host registration after a sealed container has passed P4 inspection."""
    actor, organization, asset = _management_scope(actor_id=actor_id, asset_id=asset_id)
    definition = lab_definition(lab_definition_id)
    idempotency_key = _idempotency(idempotency_key)
    if type(ttl_seconds) is not int or not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise WebLabLifecycleError('Lab TTL is outside the bounded lifecycle window.')
    if not isinstance(container_name, str) or not CONTAINER_NAME.fullmatch(container_name):
        raise WebLabLifecycleError('Unexpected Web Lab container name.')
    if not isinstance(inspection, dict):
        raise WebLabLifecycleError('Trusted runtime inspection is required.')
    required = {'target', 'instance_ref', 'process_ref', 'fixture_revision', 'variant',
                'image_id', 'container_id', 'inspected_at'}
    if set(inspection) != required:
        raise WebLabLifecycleError('Unexpected runtime inspection shape.')
    if (inspection.get('fixture_revision') != definition['fixture_revision_sha256']
            or inspection.get('variant') not in {'vulnerable', 'patched'}
            or not IMAGE_ID.fullmatch(str(inspection.get('image_id', '')))
            or not SHA256.fullmatch(str(inspection.get('container_id', '')))):
        raise WebLabLifecycleError('Runtime inspection does not match the pinned lab definition.')
    _uuid(inspection['instance_ref'], 'instance_ref')
    _uuid(inspection['process_ref'], 'process_ref')
    supersedes_ref = _uuid(supersedes_instance_id, 'supersedes_instance_id') if supersedes_instance_id else None
    payload = {
        'actor_ref': str(actor.id), 'asset_ref': str(asset.id), 'lab_ref': lab_definition_id,
        'inspection': inspection, 'container_name': container_name, 'ttl_seconds': ttl_seconds,
        'supersedes_ref': supersedes_ref,
    }
    fingerprint = _fingerprint('provision', payload)
    replay = _existing_event(
        organization_id=organization.id, idempotency_key=idempotency_key, fingerprint=fingerprint)
    if replay:
        return replay

    with transaction.atomic():
        asset = Asset.objects.select_for_update().select_related('project').get(pk=asset.id)
        replay = _existing_event(
            organization_id=organization.id, idempotency_key=idempotency_key, fingerprint=fingerprint)
        if replay:
            return replay

        authorization, reason = current_asset_authorization(asset, inspection['target'])
        if (authorization is None or dict(asset.configuration or {}).get('authorized') is not True):
            raise WebLabLifecycleAccessError(
                reason or 'Web Lab asset authorization projection is not enabled.')

        history = WebLabInstance.objects.select_for_update().filter(
            project=asset.project, asset=asset, definition_id=lab_definition_id,
        ).order_by('-generation', '-created_at', '-id')
        latest = history.first()
        previous = None
        generation = 1
        if latest is None:
            if supersedes_ref:
                raise WebLabLifecycleError('First Web Lab generation cannot supersede a prior instance.')
        else:
            if not supersedes_ref:
                raise WebLabLifecycleError(
                    'A prior Web Lab generation exists; reset must explicitly supersede the latest cleaned generation.')
            previous = history.filter(pk=supersedes_ref).first()
            if previous is None or previous.id != latest.id:
                raise WebLabLifecycleError('Reset lineage must supersede the latest Web Lab generation.')
            if previous.status != WebLabInstance.Status.CLEANED:
                raise WebLabLifecycleError('Reset lineage requires a cleaned prior generation.')
            generation = previous.generation + 1

        evidence = record_runtime_inspection(asset=asset, actor_id=str(actor.id), inspection=inspection)
        now = timezone.now()
        instance = WebLabInstance.objects.create(
            organization=organization, project=asset.project, asset=asset,
            definition_id=lab_definition_id, fixture_revision=definition['fixture_revision_sha256'],
            variant=inspection['variant'], generation=generation,
            instance_ref=inspection['instance_ref'], runtime_evidence=evidence,
            image_id=inspection['image_id'], container_id=inspection['container_id'],
            container_name=container_name, target=inspection['target'], provisioned_by=actor,
            supersedes=previous, status=WebLabInstance.Status.READY,
            expires_at=now + timedelta(seconds=ttl_seconds), version=1,
        )
        _append_event(
            instance=instance, actor_id=str(actor.id),
            event_type=WebLabLifecycleEvent.EventType.PROVISIONED,
            idempotency_key=idempotency_key, fingerprint=fingerprint, before_status='',
            runtime_evidence_id=evidence.id,
            details={'ttl_seconds': ttl_seconds, 'container_identity_sha256': _digest(instance.container_id)},
        )
        return host_instance_projection(instance)


def mark_instance_expired(*, actor_id: str, instance_id: str, idempotency_key: str) -> dict:
    instance_id = _uuid(instance_id, 'instance_id')
    idempotency_key = _idempotency(idempotency_key)
    instance = WebLabInstance.objects.select_related('asset').filter(pk=instance_id).first()
    if not instance:
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    actor, organization, _asset = _management_scope(actor_id=actor_id, asset_id=str(instance.asset_id))
    fingerprint = _fingerprint('expire', {'actor_ref': str(actor.id), 'instance_ref': instance_id})
    replay = _existing_event(
        organization_id=organization.id, idempotency_key=idempotency_key, fingerprint=fingerprint)
    if replay:
        return replay
    with transaction.atomic():
        locked = WebLabInstance.objects.select_for_update().get(pk=instance_id)
        if locked.organization_id != organization.id:
            raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
        if locked.status == WebLabInstance.Status.CLEANED:
            return host_instance_projection(locked)
        if locked.status == WebLabInstance.Status.EXPIRED:
            return host_instance_projection(locked)
        if locked.status != WebLabInstance.Status.READY or timezone.now() < locked.expires_at:
            raise WebLabLifecycleError('Web Lab instance has not reached its expiry boundary.')
        before = locked.status
        locked.status = WebLabInstance.Status.EXPIRED
        locked.version += 1
        locked.save(update_fields=['status', 'version', 'updated_at'])
        _append_event(
            instance=locked, actor_id=str(actor.id), event_type=WebLabLifecycleEvent.EventType.EXPIRED,
            idempotency_key=idempotency_key, fingerprint=fingerprint, before_status=before,
            details={'expiry_boundary': locked.expires_at.isoformat()},
        )
        return host_instance_projection(locked)


def mark_instance_cleaned(*, actor_id: str, instance_id: str, observed_container_id: str,
                          idempotency_key: str, reason: str) -> dict:
    instance_id = _uuid(instance_id, 'instance_id')
    idempotency_key = _idempotency(idempotency_key)
    if reason not in {'manual', 'reset', 'expired', 'failed'}:
        raise WebLabLifecycleError('Unsupported cleanup reason.')
    if not isinstance(observed_container_id, str) or not SHA256.fullmatch(observed_container_id):
        raise WebLabLifecycleError('Observed container identity is invalid.')
    instance = WebLabInstance.objects.select_related('asset').filter(pk=instance_id).first()
    if not instance:
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    actor, organization, _asset = _management_scope(actor_id=actor_id, asset_id=str(instance.asset_id))
    fingerprint = _fingerprint('cleanup', {
        'actor_ref': str(actor.id), 'instance_ref': instance_id,
        'container_id': observed_container_id, 'reason': reason,
    })
    replay = _existing_event(
        organization_id=organization.id, idempotency_key=idempotency_key, fingerprint=fingerprint)
    if replay:
        return replay
    with transaction.atomic():
        locked = WebLabInstance.objects.select_for_update().get(pk=instance_id)
        if locked.organization_id != organization.id or locked.container_id != observed_container_id:
            raise WebLabLifecycleError('Cleanup container identity does not match the registered instance.')
        if locked.status == WebLabInstance.Status.CLEANED:
            return host_instance_projection(locked)
        if reason == 'expired' and locked.status != WebLabInstance.Status.EXPIRED:
            raise WebLabLifecycleError('Expired cleanup requires an expired Web Lab instance.')
        if reason == 'failed' and locked.status != WebLabInstance.Status.FAILED:
            raise WebLabLifecycleError('Failed cleanup requires a failed Web Lab instance.')
        before = locked.status
        locked.status = WebLabInstance.Status.CLEANED
        locked.cleaned_at = timezone.now()
        locked.version += 1
        locked.save(update_fields=['status', 'cleaned_at', 'version', 'updated_at'])
        _append_event(
            instance=locked, actor_id=str(actor.id), event_type=WebLabLifecycleEvent.EventType.CLEANED,
            idempotency_key=idempotency_key, fingerprint=fingerprint, before_status=before,
            details={'reason': reason, 'container_identity_sha256': _digest(observed_container_id)},
        )
        return host_instance_projection(locked)


def mark_instance_failed(*, actor_id: str, instance_id: str, observed_container_id: str,
                         failure_code: str, idempotency_key: str) -> dict:
    instance_id = _uuid(instance_id, 'instance_id')
    idempotency_key = _idempotency(idempotency_key)
    if not isinstance(failure_code, str) or not FAILURE_CODE.fullmatch(failure_code):
        raise WebLabLifecycleError('Invalid lifecycle failure code.')
    instance = WebLabInstance.objects.select_related('asset').filter(pk=instance_id).first()
    if not instance:
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    actor, organization, _asset = _management_scope(actor_id=actor_id, asset_id=str(instance.asset_id))
    fingerprint = _fingerprint('fail', {
        'actor_ref': str(actor.id), 'instance_ref': instance_id,
        'container_id': observed_container_id, 'failure_code': failure_code,
    })
    replay = _existing_event(
        organization_id=organization.id, idempotency_key=idempotency_key, fingerprint=fingerprint)
    if replay:
        return replay
    with transaction.atomic():
        locked = WebLabInstance.objects.select_for_update().get(pk=instance_id)
        if locked.organization_id != organization.id or locked.container_id != observed_container_id:
            raise WebLabLifecycleError('Failed runtime does not match the registered instance.')
        if locked.status != WebLabInstance.Status.READY:
            raise WebLabLifecycleError('Only a ready Web Lab instance can transition to failed.')
        before = locked.status
        locked.status = WebLabInstance.Status.FAILED
        locked.version += 1
        locked.save(update_fields=['status', 'version', 'updated_at'])
        _append_event(
            instance=locked, actor_id=str(actor.id), event_type=WebLabLifecycleEvent.EventType.FAILED,
            idempotency_key=idempotency_key, fingerprint=fingerprint, before_status=before,
            details={'failure_code': failure_code},
        )
        return host_instance_projection(locked)


def get_web_lab_instance(*, actor_id: str, instance_id: str) -> dict:
    instance_id = _uuid(instance_id, 'instance_id')
    row = WebLabInstance.objects.select_related('project').filter(pk=instance_id).first()
    if not row:
        raise WebLabLifecycleAccessError('Web Lab lifecycle scope is unavailable.')
    _read_scope(actor_id=actor_id, project_id=str(row.project_id))
    return public_instance_projection(row)


def list_web_lab_instances(*, actor_id: str, project_id: str, asset_id: str | None = None,
                           lab_definition_id: str | None = None, limit: int = 25) -> list[dict]:
    project_id = _uuid(project_id, 'project_id')
    _read_scope(actor_id=actor_id, project_id=project_id)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise WebLabLifecycleError('Invalid lifecycle list limit.')
    query = WebLabInstance.objects.filter(project_id=project_id)
    if asset_id is not None:
        query = query.filter(asset_id=_uuid(asset_id, 'asset_id'))
    if lab_definition_id is not None:
        lab_definition(lab_definition_id)
        query = query.filter(definition_id=lab_definition_id)
    return [public_instance_projection(row) for row in query.order_by('-created_at', '-id')[:limit]]
