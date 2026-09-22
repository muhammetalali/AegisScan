from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from django.db import transaction

from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from enterprise.attack_replay_models import AttackReplayRun, AttackReplayScenario
from enterprise.models import (
    AttackPath,
    AttackPathValidation,
    Organization,
    OrganizationMembership,
    TenantProject,
)

from .audit_writer import add_audit_entry
from .validated_attack_chain import verify_attack_path_validation


ATTACK_REPLAY_POLICY_VERSION = 'attack-replay-sandbox.v1'
ATTACK_REPLAY_ISOLATION_CONTRACT = {
    'schema': 'aegis.attack-replay-isolation.v1',
    'execution_mode': 'deterministic-simulation',
    'network': 'deny',
    'filesystem': 'ephemeral-readonly',
    'credentials': 'none',
    'external_side_effects': False,
    'production_targets': False,
    'arbitrary_commands': False,
    'raw_payload_execution': False,
}
_CONTROL_OUTCOMES = {'prevented', 'detected', 'allowed', 'not_observed'}
_MAX_CONTROLS = 128


class AttackReplayError(ValueError):
    pass


class AttackReplayAuthorizationError(AttackReplayError):
    pass


class AttackReplayConflict(AttackReplayError):
    pass


@dataclass(frozen=True)
class ReplayScenarioResult:
    scenario: AttackReplayScenario
    replayed: bool


@dataclass(frozen=True)
class ReplayRunResult:
    run: AttackReplayRun
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    ).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _clean_idempotency(value: str) -> str:
    normalized = ' '.join(str(value or '').split())
    if not normalized or len(normalized) > 128 or any(ch in normalized for ch in '\r\n\x00'):
        raise AttackReplayError('idempotency_key is invalid.')
    return normalized


def _active_context(project_id: str, actor_id: str) -> tuple[Organization, Project]:
    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if identity is None:
        raise AttackReplayAuthorizationError('Project is not bound to an active enterprise tenant.')

    organization = (
        Organization.objects.select_for_update()
        .filter(pk=identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        raise AttackReplayAuthorizationError('Enterprise tenant is inactive.')

    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=identity['id'], organization=organization, project_id=project_id)
        .first()
    )
    if link is None:
        raise AttackReplayAuthorizationError('Tenant/project binding changed before replay.')

    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None:
        raise AttackReplayAuthorizationError('Project was not found.')
    if str(project.owner_id) != str(actor_id) and not project.members.filter(pk=actor_id).exists():
        raise AttackReplayAuthorizationError('Actor has no project access.')

    allowed_roles = {
        OrganizationMembership.Role.OWNER,
        OrganizationMembership.Role.ADMIN,
        OrganizationMembership.Role.MANAGER,
        OrganizationMembership.Role.ANALYST,
    }
    if not OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        user__is_active=True,
        is_active=True,
        role__in=allowed_roles,
    ).exists():
        raise AttackReplayAuthorizationError('Actor has no active enterprise replay role.')
    return organization, project


def _project_ids(evidence: Evidence) -> set[str]:
    values: set[str] = set()
    if evidence.scan_id and evidence.scan is not None:
        values.add(str(evidence.scan.project_id))
    if evidence.asset_id and evidence.asset is not None:
        values.add(str(evidence.asset.project_id))
    if evidence.finding_id and evidence.finding is not None:
        values.add(str(evidence.finding.project_id))
    return values


def _control_id(value: Any) -> str:
    normalized = ' '.join(str(value or '').split())
    if not normalized or len(normalized) > 180 or any(ch in normalized for ch in '\r\n\x00'):
        raise AttackReplayError('control_id is invalid.')
    return normalized


def _normalize_expected_controls(value: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise AttackReplayError('expected_controls must contain at least one control.')
    if len(value) > _MAX_CONTROLS:
        raise AttackReplayError('expected_controls exceeds the supported limit.')
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {'control_id', 'expected'}:
            raise AttackReplayError('Each expected control must contain only control_id and expected.')
        control_id = _control_id(raw.get('control_id'))
        expected = str(raw.get('expected') or '').strip().lower()
        if expected not in _CONTROL_OUTCOMES:
            raise AttackReplayError('Unsupported expected control outcome.')
        if control_id in seen:
            raise AttackReplayError('expected_controls contains a duplicate control_id.')
        seen.add(control_id)
        rows.append({'control_id': control_id, 'expected': expected})
    return sorted(rows, key=lambda item: item['control_id'])


def _normalize_observed_controls(
    value: list[dict[str, Any]],
    *,
    expected_ids: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise AttackReplayError('observed_controls must be a list.')
    if len(value) > _MAX_CONTROLS:
        raise AttackReplayError('observed_controls exceeds the supported limit.')
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {'control_id', 'observed', 'evidence_ids'}:
            raise AttackReplayError(
                'Each observed control must contain only control_id, observed and evidence_ids.'
            )
        control_id = _control_id(raw.get('control_id'))
        if control_id not in expected_ids:
            raise AttackReplayError('observed_controls contains a control outside the replay contract.')
        if control_id in seen:
            raise AttackReplayError('observed_controls contains a duplicate control_id.')
        seen.add(control_id)
        observed = str(raw.get('observed') or '').strip().lower()
        if observed not in _CONTROL_OUTCOMES:
            raise AttackReplayError('Unsupported observed control outcome.')
        evidence_ids = sorted({
            str(item).strip()
            for item in (raw.get('evidence_ids') or [])
            if str(item).strip()
        })
        if not evidence_ids:
            raise AttackReplayError('Every observed control requires evidence_ids.')
        rows.append({
            'control_id': control_id,
            'observed': observed,
            'evidence_ids': evidence_ids,
        })
    return sorted(rows, key=lambda item: item['control_id'])


def _current_validation(
    *,
    organization: Organization,
    project: Project,
    validation_id: str,
) -> AttackPathValidation:
    validation = (
        AttackPathValidation.objects.select_for_update()
        .select_related('attack_path', 'threat_model_snapshot', 'blast_radius_snapshot')
        .filter(pk=validation_id, organization=organization, project=project)
        .first()
    )
    if validation is None:
        raise AttackReplayAuthorizationError('Attack-path validation was not found in this tenant/project.')
    integrity = verify_attack_path_validation(validation)
    if integrity.get('valid') is not True:
        raise AttackReplayError('Attack-path validation proof integrity failed.')
    if validation.attack_path.status != AttackPath.Status.VALIDATED:
        raise AttackReplayError('Attack replay requires a currently validated attack path.')
    latest = (
        AttackPathValidation.objects.select_for_update()
        .filter(
            organization=organization,
            project=project,
            attack_path_id=validation.attack_path_id,
        )
        .order_by('-created_at', '-id')
        .first()
    )
    if latest is None or latest.id != validation.id:
        raise AttackReplayError('Attack replay requires the latest attack-path validation.')
    return validation


def _validation_evidence_snapshot(
    *,
    validation: AttackPathValidation,
    project: Project,
) -> list[dict[str, Any]]:
    requested = sorted({str(item).strip() for item in (validation.evidence_refs or []) if str(item).strip()})
    if not requested:
        raise AttackReplayError('Attack-path validation has no evidence lineage.')
    rows = list(
        Evidence.objects.select_for_update(of=('self',))
        .select_related('scan', 'asset', 'finding')
        .filter(pk__in=requested)
    )
    by_id = {str(row.id): row for row in rows}
    if set(by_id) != set(requested):
        raise AttackReplayError('Attack-path validation evidence is missing.')

    material = validation.proof_material if isinstance(validation.proof_material, dict) else {}
    allowed_assets = {str(item) for item in (material.get('steps') or []) if str(item)}
    snapshot: list[dict[str, Any]] = []
    for evidence_id in requested:
        row = by_id[evidence_id]
        if _project_ids(row) != {str(project.id)}:
            raise AttackReplayAuthorizationError('Attack replay evidence crossed the project boundary.')
        if not row.asset_id or str(row.asset_id) not in allowed_assets:
            raise AttackReplayAuthorizationError('Attack replay evidence is outside the validated attack path.')
        digest = hashlib.sha256((row.raw_output or '').encode('utf-8', errors='replace')).hexdigest()
        if not row.sha256 or digest != row.sha256:
            raise AttackReplayError(f'Attack replay evidence integrity mismatch for {row.id}.')
        snapshot.append({
            'evidence_id': str(row.id),
            'asset_id': str(row.asset_id),
            'finding_id': str(row.finding_id or ''),
            'source': str(row.source),
            'evidence_type': str(row.evidence_type),
            'sha256': row.sha256,
        })
    return sorted(snapshot, key=lambda item: item['evidence_id'])


def _scenario_integrity(scenario: AttackReplayScenario) -> bool:
    material = {
        'policy_version': scenario.policy_version,
        'isolation_contract': scenario.isolation_contract,
        'source_snapshot': scenario.source_snapshot,
        'expected_controls': scenario.expected_controls,
    }
    return _sha(material) == scenario.scenario_sha256


@transaction.atomic
def create_attack_replay_scenario(
    *,
    project_id: str,
    actor_id: str,
    attack_path_validation_id: str,
    expected_controls: list[dict[str, Any]],
    idempotency_key: str,
) -> ReplayScenarioResult:
    idem = _clean_idempotency(idempotency_key)
    organization, project = _active_context(str(project_id), str(actor_id))
    validation = _current_validation(
        organization=organization,
        project=project,
        validation_id=str(attack_path_validation_id),
    )
    expected = _normalize_expected_controls(expected_controls)
    evidence = _validation_evidence_snapshot(validation=validation, project=project)
    blast = validation.blast_radius_snapshot
    source_snapshot = {
        'schema': 'aegis.attack-replay-source.v1',
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'attack_path_validation_id': str(validation.id),
        'validation_sha256': validation.validation_sha256,
        'attack_path_id': str(validation.attack_path_id),
        'threat_model_snapshot_id': str(validation.threat_model_snapshot_id),
        'blast_radius_snapshot_id': str(validation.blast_radius_snapshot_id),
        'scenario_refs': sorted(str(item) for item in (validation.scenario_refs or [])),
        'authorization_refs': sorted(str(item) for item in (validation.authorization_refs or [])),
        'relationship_refs': sorted(str(item) for item in (validation.relationship_refs or [])),
        'path_steps': list((validation.proof_material or {}).get('steps') or []),
        'blast_radius_score': float(blast.score or 0.0),
        'crown_jewel_refs': sorted(str(item) for item in (blast.crown_jewel_refs or [])),
        'evidence': evidence,
    }
    scenario_material = {
        'policy_version': ATTACK_REPLAY_POLICY_VERSION,
        'isolation_contract': ATTACK_REPLAY_ISOLATION_CONTRACT,
        'source_snapshot': source_snapshot,
        'expected_controls': expected,
    }
    scenario_sha256 = _sha(scenario_material)
    request_fingerprint = _sha({
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'attack_path_validation_id': str(validation.id),
        'idempotency_key': idem,
        'scenario_sha256': scenario_sha256,
    })

    existing = AttackReplayScenario.objects.filter(
        organization=organization,
        idempotency_key=idem,
    ).first()
    if existing is not None:
        if existing.request_fingerprint != request_fingerprint:
            raise AttackReplayConflict('Attack replay scenario idempotency key was reused with different content.')
        if not _scenario_integrity(existing):
            raise AttackReplayConflict('Stored attack replay scenario integrity check failed.')
        return ReplayScenarioResult(scenario=existing, replayed=True)

    scenario = AttackReplayScenario.objects.create(
        organization=organization,
        project=project,
        attack_path_validation=validation,
        created_by_id=actor_id,
        isolation_contract=dict(ATTACK_REPLAY_ISOLATION_CONTRACT),
        source_snapshot=source_snapshot,
        expected_controls=expected,
        idempotency_key=idem,
        scenario_sha256=scenario_sha256,
        request_fingerprint=request_fingerprint,
        policy_version=ATTACK_REPLAY_POLICY_VERSION,
    )
    add_audit_entry(
        user=actor_id,
        action='attack_replay.scenario.create',
        target=str(scenario.id),
        project=str(project.id),
        resource_type='attack_replay_scenario',
        resource_repr=str(validation.attack_path_id),
        metadata={
            'organization_id': str(organization.id),
            'attack_path_validation_id': str(validation.id),
            'scenario_sha256': scenario_sha256,
            'policy_version': ATTACK_REPLAY_POLICY_VERSION,
            'external_side_effects': False,
        },
    )
    return ReplayScenarioResult(scenario=scenario, replayed=False)


def _observation_evidence_snapshot(
    *,
    project: Project,
    scenario: AttackReplayScenario,
    observed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    requested = sorted({
        evidence_id
        for row in observed
        for evidence_id in row['evidence_ids']
    })
    rows = list(
        Evidence.objects.select_for_update(of=('self',))
        .select_related('scan', 'asset', 'finding')
        .filter(pk__in=requested)
    )
    by_id = {str(row.id): row for row in rows}
    if set(by_id) != set(requested):
        raise AttackReplayError('One or more replay observation evidence records do not exist.')

    allowed_assets = {str(item) for item in (scenario.source_snapshot.get('path_steps') or []) if str(item)}
    supports: dict[str, list[str]] = {evidence_id: [] for evidence_id in requested}
    for row in observed:
        for evidence_id in row['evidence_ids']:
            supports[evidence_id].append(row['control_id'])

    snapshot: list[dict[str, Any]] = []
    for evidence_id in requested:
        evidence = by_id[evidence_id]
        if _project_ids(evidence) != {str(project.id)}:
            raise AttackReplayAuthorizationError('Replay observation evidence crossed the project boundary.')
        if not evidence.asset_id or str(evidence.asset_id) not in allowed_assets:
            raise AttackReplayAuthorizationError('Replay observation evidence is outside the validated attack path.')
        digest = hashlib.sha256((evidence.raw_output or '').encode('utf-8', errors='replace')).hexdigest()
        if not evidence.sha256 or digest != evidence.sha256:
            raise AttackReplayError(f'Replay observation evidence integrity mismatch for {evidence.id}.')
        snapshot.append({
            'evidence_id': str(evidence.id),
            'asset_id': str(evidence.asset_id),
            'finding_id': str(evidence.finding_id or ''),
            'sha256': evidence.sha256,
            'supports_controls': sorted(supports[evidence_id]),
        })
    return sorted(snapshot, key=lambda item: item['evidence_id'])


@transaction.atomic
def run_attack_replay(
    *,
    project_id: str,
    scenario_id: str,
    actor_id: str,
    observed_controls: list[dict[str, Any]],
    idempotency_key: str,
) -> ReplayRunResult:
    idem = _clean_idempotency(idempotency_key)
    organization, project = _active_context(str(project_id), str(actor_id))
    scenario = (
        AttackReplayScenario.objects.select_for_update()
        .select_related('attack_path_validation')
        .filter(pk=scenario_id, organization=organization, project=project)
        .first()
    )
    if scenario is None:
        raise AttackReplayAuthorizationError('Attack replay scenario was not found in this tenant/project.')
    if scenario.policy_version != ATTACK_REPLAY_POLICY_VERSION or scenario.isolation_contract != ATTACK_REPLAY_ISOLATION_CONTRACT:
        raise AttackReplayError('Attack replay isolation contract is not currently accepted.')
    if not _scenario_integrity(scenario):
        raise AttackReplayError('Attack replay scenario integrity check failed.')

    validation = _current_validation(
        organization=organization,
        project=project,
        validation_id=str(scenario.attack_path_validation_id),
    )
    if validation.validation_sha256 != scenario.source_snapshot.get('validation_sha256'):
        raise AttackReplayError('Attack-path validation drifted after replay scenario creation.')

    expected = {
        row['control_id']: row['expected']
        for row in scenario.expected_controls
    }
    observed = _normalize_observed_controls(
        observed_controls,
        expected_ids=set(expected),
    )
    evidence_snapshot = _observation_evidence_snapshot(
        project=project,
        scenario=scenario,
        observed=observed,
    )
    observed_map = {row['control_id']: row['observed'] for row in observed}
    comparison = []
    for control_id in sorted(expected):
        expected_value = expected[control_id]
        observed_value = observed_map.get(control_id, 'not_observed')
        comparison.append({
            'control_id': control_id,
            'expected': expected_value,
            'observed': observed_value,
            'matches': expected_value == observed_value,
        })

    matched = sum(1 for row in comparison if row['matches'])
    outcome = (
        AttackReplayRun.Outcome.MATCHED
        if matched == len(comparison)
        else AttackReplayRun.Outcome.DIVERGED
    )
    input_snapshot = {
        'schema': 'aegis.attack-replay-input.v1',
        'scenario_id': str(scenario.id),
        'scenario_sha256': scenario.scenario_sha256,
        'observed_controls': observed,
        'observation_evidence': evidence_snapshot,
        'isolation_contract': dict(ATTACK_REPLAY_ISOLATION_CONTRACT),
    }
    input_sha256 = _sha(input_snapshot)
    comparison_sha256 = _sha(comparison)
    result_snapshot = {
        'schema': 'aegis.attack-replay-result.v1',
        'outcome': outcome,
        'control_count': len(comparison),
        'matched_controls': matched,
        'divergent_controls': len(comparison) - matched,
        'match_ratio': round(matched / len(comparison), 6) if comparison else 1.0,
        'comparison': comparison,
        'comparison_sha256': comparison_sha256,
        'validation_sha256': validation.validation_sha256,
        'external_side_effects': False,
        'production_execution_performed': False,
        'network_access_performed': False,
        'credentials_used': False,
    }
    result_sha256 = _sha(result_snapshot)
    request_fingerprint = _sha({
        'scenario_id': str(scenario.id),
        'actor_id': str(actor_id),
        'idempotency_key': idem,
        'input_sha256': input_sha256,
    })

    existing = AttackReplayRun.objects.filter(
        scenario=scenario,
        idempotency_key=idem,
    ).first()
    if existing is not None:
        if existing.request_fingerprint != request_fingerprint:
            raise AttackReplayConflict('Attack replay run idempotency key was reused with different content.')
        if _sha(existing.result_snapshot or {}) != existing.result_sha256:
            raise AttackReplayConflict('Stored attack replay result integrity check failed.')
        return ReplayRunResult(run=existing, replayed=True)

    run = AttackReplayRun.objects.create(
        organization=organization,
        project=project,
        scenario=scenario,
        executed_by_id=actor_id,
        observed_controls=observed,
        observation_evidence=evidence_snapshot,
        result_snapshot=result_snapshot,
        outcome=outcome,
        input_sha256=input_sha256,
        result_sha256=result_sha256,
        comparison_sha256=comparison_sha256,
        idempotency_key=idem,
        request_fingerprint=request_fingerprint,
        policy_version=ATTACK_REPLAY_POLICY_VERSION,
    )
    add_audit_entry(
        user=actor_id,
        action='attack_replay.run.commit',
        target=str(run.id),
        project=str(project.id),
        resource_type='attack_replay_run',
        resource_repr=str(scenario.id),
        metadata={
            'organization_id': str(organization.id),
            'scenario_id': str(scenario.id),
            'attack_path_validation_id': str(validation.id),
            'outcome': outcome,
            'input_sha256': input_sha256,
            'result_sha256': result_sha256,
            'comparison_sha256': comparison_sha256,
            'policy_version': ATTACK_REPLAY_POLICY_VERSION,
            'external_side_effects': False,
        },
    )
    return ReplayRunResult(run=run, replayed=False)
