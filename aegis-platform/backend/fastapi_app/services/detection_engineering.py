from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from django_project.evidence.models import Evidence
from django_project.vulnerabilities.models import Vulnerability
from enterprise.detection_models import (
    DetectionEvent,
    DetectionPublication,
    DetectionPublicationDelivery,
    DetectionRevision,
    DetectionRule,
    DetectionValidation,
)
from enterprise.governed_action_models import GovernedActionRequest
from enterprise.integrations import send_integration
from enterprise.models import ExternalIntegration, OrganizationMembership, TenantProject
from fastapi_app.services.integration_live_acceptance import (
    current_integration_live_acceptance,
    integration_configuration_fingerprint,
)


_TECHNIQUE_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$')
_FIELD_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,127}$')
_SIMPLE_KUSTO_FIELD_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_ALLOWED_OPERATORS = {'equals', 'contains', 'in', 'exists'}
_ALLOWED_CONDITIONS = {'all', 'any'}
_AUTHOR_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
    OrganizationMembership.Role.ANALYST,
}
_PUBLISH_ROLES = {
    OrganizationMembership.Role.OWNER,
    OrganizationMembership.Role.ADMIN,
    OrganizationMembership.Role.MANAGER,
}
_SIEM_KINDS = {
    ExternalIntegration.Kind.SPLUNK,
    ExternalIntegration.Kind.ELASTIC,
    ExternalIntegration.Kind.SENTINEL,
    ExternalIntegration.Kind.QRADAR,
}


class DetectionEngineeringError(ValueError):
    pass


@dataclass(frozen=True)
class RevisionResult:
    revision: DetectionRevision
    replayed: bool


@dataclass(frozen=True)
class ValidationResult:
    validation: DetectionValidation
    replayed: bool


@dataclass(frozen=True)
class PublicationResult:
    publication: DetectionPublication
    replayed: bool


@dataclass(frozen=True)
class PublicationDeliveryResult:
    delivery: DetectionPublicationDelivery
    replayed: bool


@dataclass(frozen=True)
class PublicationDeliveryExecutionResult:
    delivery: DetectionPublicationDelivery
    publication: DetectionPublication | None
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _membership(project_id: str, user_id: str, allowed_roles: set[str]):
    link = TenantProject.objects.select_related('organization', 'project').filter(project_id=project_id).first()
    if link is None:
        raise DetectionEngineeringError('Project is not bound to an enterprise tenant.')
    membership = OrganizationMembership.objects.filter(
        organization=link.organization,
        user_id=user_id,
        is_active=True,
        user__is_active=True,
        role__in=allowed_roles,
    ).first()
    if membership is None:
        raise PermissionError('Active tenant role does not permit this detection operation.')
    return link, membership


def _normalized_spec(spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise DetectionEngineeringError('Detection spec must be an object.')
    allowed = {'logsource', 'condition', 'match', 'severity', 'attack_techniques', 'description'}
    unknown = sorted(set(spec) - allowed)
    if unknown:
        raise DetectionEngineeringError(f'Unsupported detection spec fields: {", ".join(unknown)}')
    logsource = str(spec.get('logsource') or '').strip()
    if not logsource or len(logsource) > 120:
        raise DetectionEngineeringError('logsource is required and must be at most 120 characters.')
    condition = str(spec.get('condition') or 'all').lower().strip()
    if condition not in _ALLOWED_CONDITIONS:
        raise DetectionEngineeringError('condition must be all or any.')
    raw_match = spec.get('match')
    if not isinstance(raw_match, list) or not raw_match or len(raw_match) > 64:
        raise DetectionEngineeringError('match must contain between 1 and 64 predicates.')
    predicates = []
    for raw in raw_match:
        if not isinstance(raw, dict) or set(raw) - {'field', 'operator', 'value'}:
            raise DetectionEngineeringError('Each predicate must contain only field, operator, and value.')
        field = str(raw.get('field') or '').strip()
        operator = str(raw.get('operator') or '').lower().strip()
        if not _FIELD_RE.fullmatch(field):
            raise DetectionEngineeringError(f'Invalid detection field: {field!r}.')
        if operator not in _ALLOWED_OPERATORS:
            raise DetectionEngineeringError(f'Unsupported operator: {operator!r}.')
        value = raw.get('value')
        if operator == 'exists':
            value = bool(value if value is not None else True)
        elif operator == 'in':
            if not isinstance(value, list) or not value or len(value) > 64:
                raise DetectionEngineeringError('in operator requires a non-empty list of at most 64 values.')
            if any(isinstance(x, (dict, list)) for x in value):
                raise DetectionEngineeringError('in values must be scalar.')
        elif isinstance(value, (dict, list)) or value is None:
            raise DetectionEngineeringError(f'{operator} requires a scalar value.')
        predicates.append({'field': field, 'operator': operator, 'value': value})
    techniques = sorted({str(x).upper().strip() for x in (spec.get('attack_techniques') or []) if str(x).strip()})
    if not techniques or len(techniques) > 64 or any(not _TECHNIQUE_RE.fullmatch(x) for x in techniques):
        raise DetectionEngineeringError('attack_techniques must contain 1-64 valid ATT&CK technique IDs.')
    severity = str(spec.get('severity') or 'medium').lower().strip()
    if severity not in {'info', 'low', 'medium', 'high', 'critical'}:
        raise DetectionEngineeringError('severity must be info, low, medium, high, or critical.')
    description = str(spec.get('description') or '').strip()
    if len(description) > 4000:
        raise DetectionEngineeringError('description must be at most 4000 characters.')
    return {
        'logsource': logsource,
        'condition': condition,
        'match': predicates,
        'severity': severity,
        'attack_techniques': techniques,
        'description': description,
    }


def _escape_string(value: Any) -> str:
    return str(value).replace('\\', '\\\\').replace('"', '\\"')


def _sentinel_field(field: str) -> str:
    if _SIMPLE_KUSTO_FIELD_RE.fullmatch(field):
        return field
    return "['" + field.replace("'", "''") + "']"


def _compile_predicate(predicate: dict[str, Any], target: str) -> str:
    field, operator, value = predicate['field'], predicate['operator'], predicate['value']
    if target == 'sentinel_kql':
        kfield = _sentinel_field(field)
        if operator == 'exists':
            return f'isnotnull({kfield})' if bool(value) else f'isnull({kfield})'
        if operator == 'in':
            values = ','.join(f'"{_escape_string(x)}"' for x in value)
            return f'{kfield} in ({values})'
        escaped = _escape_string(value)
        if operator == 'equals':
            return f'{kfield} == "{escaped}"'
        return f'{kfield} contains "{escaped}"'
    if operator == 'exists':
        expected = bool(value)
        if target == 'splunk': return f'{field}=*' if expected else f'NOT {field}=*'
        if target == 'elastic_kql': return f'{field}:*' if expected else f'NOT {field}:*'
        return f'{field} IS NOT NULL' if expected else f'{field} IS NULL'
    if operator == 'in':
        values = [_escape_string(x) for x in value]
        if target == 'splunk': return f'{field} IN (' + ','.join(f'"{x}"' for x in values) + ')'
        if target == 'elastic_kql': return '(' + ' OR '.join(f'{field}:"{x}"' for x in values) + ')'
        return f'{field} IN (' + ','.join("'" + x.replace("'", "''") + "'" for x in values) + ')'
    escaped = _escape_string(value)
    if operator == 'equals':
        if target == 'splunk': return f'{field}="{escaped}"'
        if target == 'elastic_kql': return f'{field}:"{escaped}"'
        return f"{field}='" + escaped.replace("'", "''") + "'"
    if target == 'splunk': return f'{field}="*{escaped}*"'
    if target == 'elastic_kql': return f'{field}:*"{escaped}"*'
    return f"{field} ILIKE '%" + escaped.replace("'", "''") + "%'"


def compile_spec(spec: dict[str, Any]) -> dict[str, str]:
    normalized = _normalized_spec(spec)
    result = {}
    for target in ('splunk', 'elastic_kql', 'sentinel_kql', 'qradar_aql'):
        joiner = (' and ' if normalized['condition'] == 'all' else ' or ') if target == 'sentinel_kql' else (' AND ' if normalized['condition'] == 'all' else ' OR ')
        predicates = [_compile_predicate(p, target) for p in normalized['match']]
        expression = joiner.join(f'({p})' for p in predicates)
        if target == 'splunk': result[target] = f'search {expression}'
        elif target == 'qradar_aql': result[target] = f'SELECT * FROM events WHERE {expression}'
        else: result[target] = expression
    return result


def _lookup(event: dict[str, Any], field: str):
    current: Any = event
    for part in field.split('.'):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _matches(event: dict[str, Any], spec: dict[str, Any]) -> bool:
    results = []
    for predicate in spec['match']:
        present, actual = _lookup(event, predicate['field'])
        operator, expected = predicate['operator'], predicate['value']
        if operator == 'exists': outcome = present is bool(expected)
        elif not present: outcome = False
        elif operator == 'equals': outcome = actual == expected
        elif operator == 'contains': outcome = str(expected).casefold() in str(actual).casefold()
        elif operator == 'in': outcome = actual in expected
        else: outcome = False
        results.append(outcome)
    return all(results) if spec['condition'] == 'all' else any(results)


def _append_event(rule: DetectionRule, actor_id: str, event_type: str, payload: dict[str, Any], revision: DetectionRevision | None = None):
    previous = rule.events.order_by('-id').first()
    envelope = {
        'rule_id': str(rule.id), 'revision_id': str(revision.id) if revision else None,
        'event_type': event_type, 'payload': payload,
        'previous_entry_sha256': previous.entry_sha256 if previous else '',
    }
    return DetectionEvent.objects.create(
        rule=rule, revision=revision, actor_id=actor_id, event_type=event_type,
        payload={**payload, 'previous_entry_sha256': envelope['previous_entry_sha256']},
        entry_sha256=_sha(envelope),
    )


def create_revision(*, project_id: str, user_id: str, slug: str, title: str, description: str,
                    finding_id: str, evidence_id: str | None, spec: dict[str, Any]) -> RevisionResult:
    normalized = _normalized_spec(spec)
    compiled = compile_spec(normalized)
    content_sha = _sha({'contract_version': 'aegis-detection.v1', 'spec': normalized, 'compiled': compiled})
    link, _ = _membership(project_id, user_id, _AUTHOR_ROLES)
    with transaction.atomic():
        finding = Vulnerability.objects.select_for_update().filter(pk=finding_id, project_id=project_id).first()
        if finding is None:
            raise DetectionEngineeringError('Source finding does not belong to the project.')
        evidence = None
        if evidence_id:
            evidence = Evidence.objects.filter(pk=evidence_id, finding=finding).first()
            if evidence is None:
                raise DetectionEngineeringError('Source evidence is not bound to the source finding.')
        rule, created = DetectionRule.objects.select_for_update().get_or_create(
            organization=link.organization, project_id=project_id, slug=slug,
            defaults={'title': title, 'description': description, 'created_by_id': user_id},
        )
        if rule.state == DetectionRule.State.RETIRED:
            raise DetectionEngineeringError('Retired detection rules cannot receive new revisions.')
        existing = rule.revisions.filter(content_sha256=content_sha).first()
        if existing:
            if str(existing.source_finding_id) != str(finding.id) or str(existing.source_evidence_id or '') != str(evidence.id if evidence else ''):
                raise DetectionEngineeringError('Identical detection content is already bound to different source lineage.')
            return RevisionResult(existing, True)
        version = (rule.revisions.aggregate(v=Max('version'))['v'] or 0) + 1
        revision = DetectionRevision.objects.create(
            rule=rule, version=version, spec=normalized, compiled=compiled,
            attack_techniques=normalized['attack_techniques'], content_sha256=content_sha,
            source_finding=finding, source_evidence=evidence, created_by_id=user_id,
        )
        if not created:
            rule.title = title; rule.description = description; rule.state = DetectionRule.State.DRAFT
            rule.save(update_fields=['title', 'description', 'state', 'updated_at'])
        _append_event(rule, user_id, 'revision.created', {
            'version': version, 'content_sha256': content_sha,
            'source_finding_id': str(finding.id), 'source_evidence_id': str(evidence.id) if evidence else None,
            'attack_techniques': normalized['attack_techniques'],
        }, revision)
        return RevisionResult(revision, False)


def validate_revision(*, revision_id: str, project_id: str, user_id: str, telemetry: list[dict[str, Any]], minimum_matches: int = 1) -> ValidationResult:
    _membership(project_id, user_id, _AUTHOR_ROLES)
    if not telemetry or len(telemetry) > 5000 or any(not isinstance(x, dict) for x in telemetry):
        raise DetectionEngineeringError('telemetry must contain 1-5000 event objects.')
    if minimum_matches < 1 or minimum_matches > len(telemetry):
        raise DetectionEngineeringError('minimum_matches must be between 1 and telemetry length.')
    canonical_events = sorted((_canonical(x).decode('utf-8') for x in telemetry))
    telemetry_sha = hashlib.sha256(('[' + ','.join(canonical_events) + ']').encode('utf-8')).hexdigest()
    with transaction.atomic():
        revision = DetectionRevision.objects.select_for_update().filter(pk=revision_id, rule__project_id=project_id).first()
        if revision is None:
            raise DetectionEngineeringError('Detection revision not found in project.')
        rule = DetectionRule.objects.select_for_update().get(pk=revision.rule_id)
        existing = DetectionValidation.objects.filter(revision=revision, telemetry_sha256=telemetry_sha, minimum_matches=minimum_matches).first()
        if existing:
            return ValidationResult(existing, True)
        matched_fingerprints = [_sha(event) for event in telemetry if _matches(event, revision.spec)]
        matched_count = len(matched_fingerprints)
        status = DetectionValidation.Status.PASSED if matched_count >= minimum_matches else DetectionValidation.Status.FAILED
        result = {
            'matched_count': matched_count, 'telemetry_count': len(telemetry), 'minimum_matches': minimum_matches,
            'matched_event_sha256': matched_fingerprints, 'content_sha256': revision.content_sha256,
        }
        validation = DetectionValidation.objects.create(
            revision=revision, telemetry_sha256=telemetry_sha, telemetry_count=len(telemetry),
            matched_count=matched_count, minimum_matches=minimum_matches, status=status,
            result_sha256=_sha(result), result=result, tested_by_id=user_id,
        )
        latest = rule.revisions.order_by('-version').first()
        if status == DetectionValidation.Status.PASSED and latest and latest.id == revision.id:
            rule.state = DetectionRule.State.VALIDATED
            rule.save(update_fields=['state', 'updated_at'])
        _append_event(rule, user_id, 'validation.completed', {
            'validation_id': str(validation.id), 'status': status, 'telemetry_sha256': telemetry_sha,
            'matched_count': matched_count, 'minimum_matches': minimum_matches, 'result_sha256': validation.result_sha256,
        }, revision)
        return ValidationResult(validation, False)


def _publication_package(
    *,
    revision: DetectionRevision,
    rule: DetectionRule,
    integration: ExternalIntegration,
    delivery_id: uuid.UUID,
    governed_request_id: str,
) -> dict[str, Any]:
    target = {
        ExternalIntegration.Kind.SPLUNK: 'splunk',
        ExternalIntegration.Kind.ELASTIC: 'elastic_kql',
        ExternalIntegration.Kind.SENTINEL: 'sentinel_kql',
        ExternalIntegration.Kind.QRADAR: 'qradar_aql',
    }[integration.kind]
    return {
        'type': 'aegisscan.detection.package',
        'contract_version': revision.contract_version,
        'delivery_id': str(delivery_id),
        'governed_request_id': str(governed_request_id),
        'rule_id': str(rule.id),
        'revision_id': str(revision.id),
        'version': revision.version,
        'title': rule.title,
        'severity': revision.spec['severity'],
        'logsource': revision.spec['logsource'],
        'attack_techniques': revision.attack_techniques,
        'query_target': target,
        'query': revision.compiled[target],
        'content_sha256': revision.content_sha256,
        'source_finding_id': str(revision.source_finding_id),
        'source_evidence_id': str(revision.source_evidence_id) if revision.source_evidence_id else None,
    }


def queue_publication_delivery(
    *,
    revision_id: str,
    integration_id: str,
    project_id: str,
    user_id: str,
    expected_version: int,
    governed_request_id: str,
    correlation_id: str,
) -> PublicationDeliveryResult:
    """
    Persist the publication intent inside the caller's transaction. The remote
    SIEM side effect is deliberately deferred until transaction.on_commit so a
    failed AGOM audit/execution can never leave an untracked external publish.
    """
    link, _ = _membership(project_id, user_id, _PUBLISH_ROLES)
    with transaction.atomic():
        request = (
            GovernedActionRequest.objects.select_related('organization')
            .filter(
                pk=governed_request_id,
                organization=link.organization,
                project_id=project_id,
                action_id='detection.publish',
                entity_type='detection_revision',
                entity_id=str(revision_id),
                expected_version=int(expected_version),
            )
            .first()
        )
        if request is None:
            raise DetectionEngineeringError('Detection publication requires its exact immutable governed request.')
        if str(request.requested_by_id) == str(user_id):
            raise PermissionError('Detection publication approver must differ from the governed request proposer.')
        if str((request.parameters_snapshot or {}).get('integration_id') or '') != str(integration_id):
            raise DetectionEngineeringError('Governed request integration_id does not match the publication target.')

        existing = (
            DetectionPublicationDelivery.objects.select_related('revision', 'integration', 'live_acceptance')
            .filter(governed_request=request)
            .first()
        )
        if existing is not None:
            if (
                str(existing.revision_id) != str(revision_id)
                or str(existing.integration_id) != str(integration_id)
                or int(existing.revision.version + existing.revision.publication_deliveries.count() - 1) < int(expected_version)
            ):
                raise DetectionEngineeringError('Governed request is already bound to a different publication delivery.')
            return PublicationDeliveryResult(existing, True)

        revision = (
            DetectionRevision.objects.select_related('rule')
            .filter(pk=revision_id, rule__project_id=project_id, rule__organization=link.organization)
            .first()
        )
        if revision is None:
            raise DetectionEngineeringError('Detection revision not found in the governed project.')
        rule = DetectionRule.objects.select_for_update().get(pk=revision.rule_id)
        latest = rule.revisions.order_by('-version').first()
        if latest is None or latest.id != revision.id:
            raise DetectionEngineeringError('Only the latest detection revision may be published.')
        if not revision.validations.filter(status=DetectionValidation.Status.PASSED).exists():
            raise DetectionEngineeringError('A passed telemetry validation is required before publication.')

        current_version = revision.version + DetectionPublicationDelivery.objects.filter(revision=revision).count()
        if int(current_version) != int(expected_version):
            raise DetectionEngineeringError(
                f'Expected detection publication version {expected_version}, current version is {current_version}.'
            )

        integration = (
            ExternalIntegration.objects.select_for_update()
            .filter(
                pk=integration_id,
                organization=link.organization,
                enabled=True,
                kind__in=_SIEM_KINDS,
            )
            .first()
        )
        if integration is None:
            raise DetectionEngineeringError('Active tenant-owned SIEM integration not found.')
        live_acceptance = current_integration_live_acceptance(
            integration=integration,
            project_id=str(project_id),
        )
        if live_acceptance is None:
            raise DetectionEngineeringError(
                'Detection publication requires a current live-accepted SIEM integration.'
            )

        delivery_id = uuid.uuid4()
        package = _publication_package(
            revision=revision,
            rule=rule,
            integration=integration,
            delivery_id=delivery_id,
            governed_request_id=str(request.id),
        )
        package_sha = _sha(package)
        configuration_fingerprint = integration_configuration_fingerprint(integration)
        delivery = DetectionPublicationDelivery.objects.create(
            id=delivery_id,
            organization=link.organization,
            project_id=project_id,
            revision=revision,
            integration=integration,
            live_acceptance=live_acceptance,
            governed_request=request,
            correlation_id=uuid.UUID(str(correlation_id)),
            package=package,
            package_sha256=package_sha,
            integration_configuration_fingerprint=configuration_fingerprint,
            requested_by_id=user_id,
        )
        _append_event(
            rule,
            user_id,
            'publication.queued',
            {
                'delivery_id': str(delivery.id),
                'integration_id': str(integration.id),
                'live_acceptance_id': str(live_acceptance.id),
                'package_sha256': package_sha,
                'configuration_fingerprint': configuration_fingerprint,
                'governed_request_id': str(request.id),
            },
            revision,
        )

        def _queue_delivery() -> None:
            from enterprise.tasks import deliver_detection_publication

            deliver_detection_publication.delay(str(delivery.id))

        transaction.on_commit(_queue_delivery, robust=True)
        return PublicationDeliveryResult(delivery, False)


def deliver_publication_delivery(*, delivery_id: str) -> PublicationDeliveryExecutionResult:
    """
    Execute one durable publication attempt outside the database transaction.
    Automatic retries intentionally never resend SENDING/FAILED deliveries:
    after an ambiguous transport outcome a new governed request is required.
    """
    with transaction.atomic():
        delivery = (
            DetectionPublicationDelivery.objects.select_for_update()
            .select_related('revision__rule', 'integration', 'live_acceptance')
            .filter(pk=delivery_id)
            .first()
        )
        if delivery is None:
            raise DetectionEngineeringError('Detection publication delivery was not found.')
        existing_publication = DetectionPublication.objects.filter(
            revision=delivery.revision,
            integration=delivery.integration,
            package_sha256=delivery.package_sha256,
        ).first()
        if delivery.status == DetectionPublicationDelivery.Status.DELIVERED:
            return PublicationDeliveryExecutionResult(delivery, existing_publication, True)
        if delivery.status != DetectionPublicationDelivery.Status.QUEUED:
            return PublicationDeliveryExecutionResult(delivery, existing_publication, True)

        integration = (
            ExternalIntegration.objects.select_for_update()
            .filter(pk=delivery.integration_id, organization=delivery.organization)
            .first()
        )
        acceptance = (
            current_integration_live_acceptance(
                integration=integration,
                project_id=str(delivery.project_id),
            )
            if integration is not None else None
        )
        configuration_fingerprint = (
            integration_configuration_fingerprint(integration)
            if integration is not None else ''
        )
        if (
            integration is None
            or not integration.enabled
            or integration.kind not in _SIEM_KINDS
            or acceptance is None
            or str(acceptance.id) != str(delivery.live_acceptance_id)
            or configuration_fingerprint != delivery.integration_configuration_fingerprint
        ):
            delivery.status = DetectionPublicationDelivery.Status.BLOCKED
            delivery.last_error = 'Live acceptance or connector configuration changed before transport.'
            delivery.save(update_fields=['status', 'last_error', 'updated_at'])
            return PublicationDeliveryExecutionResult(delivery, None, False)

        delivery.status = DetectionPublicationDelivery.Status.SENDING
        delivery.attempts += 1
        delivery.last_error = ''
        delivery.save(update_fields=['status', 'attempts', 'last_error', 'updated_at'])
        integration_snapshot = integration
        package = dict(delivery.package or {})

    try:
        response = send_integration(integration_snapshot, package)
        response_sha = _sha(response)
    except Exception as exc:
        with transaction.atomic():
            current = DetectionPublicationDelivery.objects.select_for_update().get(pk=delivery_id)
            if current.status == DetectionPublicationDelivery.Status.SENDING:
                current.status = DetectionPublicationDelivery.Status.FAILED
                current.last_error = f'{type(exc).__name__}: {str(exc)}'[:2000]
                current.save(update_fields=['status', 'last_error', 'updated_at'])
        raise

    with transaction.atomic():
        current = (
            DetectionPublicationDelivery.objects.select_for_update()
            .select_related('revision__rule', 'integration')
            .get(pk=delivery_id)
        )
        if current.status == DetectionPublicationDelivery.Status.DELIVERED:
            publication = DetectionPublication.objects.filter(
                revision=current.revision,
                integration=current.integration,
                package_sha256=current.package_sha256,
            ).first()
            return PublicationDeliveryExecutionResult(current, publication, True)
        if current.status != DetectionPublicationDelivery.Status.SENDING:
            raise DetectionEngineeringError(
                'Detection publication delivery state changed after transport; automatic resend is forbidden.'
            )
        rule = DetectionRule.objects.select_for_update().get(pk=current.revision.rule_id)
        publication = DetectionPublication.objects.create(
            revision=current.revision,
            integration=current.integration,
            package_sha256=current.package_sha256,
            provider=current.integration.kind,
            transport_status=response.get('http_status') if isinstance(response, dict) else None,
            response_sha256=response_sha,
            published_by_id=current.requested_by_id,
        )
        rule.state = DetectionRule.State.PUBLISHED
        rule.save(update_fields=['state', 'updated_at'])
        _append_event(
            rule,
            str(current.requested_by_id),
            'publication.completed',
            {
                'publication_id': str(publication.id),
                'delivery_id': str(current.id),
                'integration_id': str(current.integration_id),
                'provider': current.integration.kind,
                'package_sha256': current.package_sha256,
                'response_sha256': response_sha,
                'transport_status': publication.transport_status,
                'live_acceptance_id': str(current.live_acceptance_id),
            },
            current.revision,
        )
        current.status = DetectionPublicationDelivery.Status.DELIVERED
        current.transport_status = publication.transport_status
        current.response_sha256 = response_sha
        current.sent_at = timezone.now()
        current.last_error = ''
        current.save(
            update_fields=[
                'status',
                'transport_status',
                'response_sha256',
                'sent_at',
                'last_error',
                'updated_at',
            ]
        )
        return PublicationDeliveryExecutionResult(current, publication, False)


def publish_revision(*, revision_id: str, integration_id: str, project_id: str, user_id: str) -> PublicationResult:
    _membership(project_id, user_id, _PUBLISH_ROLES)
    raise DetectionEngineeringError(
        'Direct detection publication is disabled; use the request-bound AGOM detection.publish action.'
    )
