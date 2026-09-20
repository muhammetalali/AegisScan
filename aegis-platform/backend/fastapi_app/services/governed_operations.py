from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from fastapi_app.contracts.governed_operations import (
    AGOM_CONTRACT_VERSION,
    ActionContract,
    ActionMode,
    ActorLayer,
    CapabilityItem,
    CapabilityManifest,
    EntityRef,
    GateResult,
    GateState,
    GateType,
    ProjectionSnapshot,
)


_POLICY_VERSION = 'agom-governance.v1'


def _contract(
    action_id: str,
    entity_type: str,
    intent: str,
    allowed_states: list[str],
    actor_layers: list[ActorLayer],
    allowed_roles: list[str],
    *,
    responsibilities: list[str] | None = None,
    gates: list[GateType] | None = None,
    evidence: list[str] | None = None,
    sod: list[str] | None = None,
    time_aware: bool = False,
    side_effects: list[str] | None = None,
    resulting_projection: dict[str, str] | None = None,
    audit_event: str,
) -> ActionContract:
    return ActionContract(
        action_id=action_id,
        entity_type=entity_type,
        intent=intent,
        allowed_states=allowed_states,
        actor_layers=actor_layers,
        allowed_roles=allowed_roles,
        required_responsibilities=responsibilities or [],
        required_gates=gates or [],
        evidence_requirements=evidence or [],
        sod_rules=sod or [],
        time_aware=time_aware,
        side_effects=side_effects or [],
        resulting_projection=resulting_projection or {},
        audit_event=audit_event,
        policy_version=_POLICY_VERSION,
    )


_ACTIONS = (
    _contract(
        'asset.authorization.approve', 'asset_authorization', 'Approve asset scope authorization',
        ['submitted'], [ActorLayer.GOVERN], ['owner', 'admin'],
        responsibilities=['authorization_approver'],
        gates=[GateType.AUTHORIZATION], evidence=['ownership', 'scope'],
        resulting_projection={'lifecycle': 'approved'}, audit_event='asset.authorization.approved',
    ),
    _contract(
        'finding.confirm', 'finding', 'Confirm a finding as technically real',
        ['pending_confirmation'], [ActorLayer.ASSURE], ['analyst', 'manager', 'admin', 'owner'],
        responsibilities=['finding_confirmer'],
        gates=[GateType.EVIDENCE], evidence=['finding_confirmation_evidence'],
        sod=['actor_must_not_be_finding_creator'],
        resulting_projection={'lifecycle': 'confirmed'}, audit_event='finding.confirmed',
    ),
    _contract(
        'finding.false_positive', 'finding', 'Classify an open finding as a validated false positive',
        ['pending_confirmation'], [ActorLayer.ASSURE], ['analyst', 'manager', 'admin', 'owner'],
        responsibilities=['finding_confirmer'],
        gates=[GateType.EVIDENCE], evidence=['finding_confirmation_evidence'],
        sod=['actor_must_not_be_finding_creator'],
        resulting_projection={'lifecycle': 'false_positive'}, audit_event='finding.false_positive',
    ),
    _contract(
        'finding.disposition.accept_risk', 'finding', 'Approve an accepted-risk disposition',
        ['confirmed'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['risk_approver'],
        gates=[GateType.EVIDENCE, GateType.EXPIRY_REVIEW],
        evidence=['risk_correlation_snapshot', 'disposition_rationale'],
        sod=['actor_must_not_be_disposition_proposer'], time_aware=True,
        resulting_projection={'governance': 'accepted_risk'}, audit_event='finding.disposition.approved',
    ),
    _contract(
        'finding.disposition.wont_fix', 'finding', 'Approve a wont-fix disposition',
        ['confirmed', 'accepted_risk'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['risk_approver'],
        gates=[GateType.EVIDENCE, GateType.EXPIRY_REVIEW],
        evidence=['risk_correlation_snapshot', 'disposition_rationale'],
        sod=['actor_must_not_be_disposition_proposer'], time_aware=True,
        resulting_projection={'governance': 'wont_fix'}, audit_event='finding.disposition.approved',
    ),
    _contract(
        'finding.disposition.duplicate', 'finding', 'Approve a duplicate disposition',
        ['pending_confirmation', 'confirmed'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['risk_approver'],
        gates=[GateType.VALIDATION],
        evidence=[],
        sod=['actor_must_not_be_disposition_proposer'],
        resulting_projection={'governance': 'duplicate'}, audit_event='finding.disposition.approved',
    ),
    _contract(
        'finding.close', 'finding', 'Close a verified finding',
        ['verified'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['closure_approver'],
        gates=[GateType.CLOSURE, GateType.INDEPENDENT_VERIFICATION],
        evidence=['remediation_verification', 'closure_proof'],
        sod=['actor_must_not_be_remediation_verifier'],
        resulting_projection={'lifecycle': 'closed'}, audit_event='finding.closed',
    ),
    _contract(
        'campaign.objective.assess', 'crown_jewel_objective', 'Record a governed objective assessment',
        ['defined', 'assessing'], [ActorLayer.OPERATE, ActorLayer.ASSURE], ['analyst', 'manager', 'admin', 'owner'],
        responsibilities=['campaign_assessor'],
        gates=[GateType.AUTHORIZATION, GateType.EVIDENCE, GateType.VALIDATION],
        evidence=['attack_path', 'objective_evidence'],
        side_effects=['append_objective_assessment', 'append_campaign_event'],
        resulting_projection={'lifecycle': 'assessing'}, audit_event='objective.assessed',
    ),
    _contract(
        'campaign.complete', 'campaign', 'Complete a campaign after all objectives are governed',
        ['active', 'assessing'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['campaign_lead'],
        gates=[GateType.AUTHORIZATION, GateType.CLOSURE, GateType.EVIDENCE],
        evidence=['terminal_objective_assessments', 'completion_proof'],
        sod=['lead_must_not_be_sole_assessor_for_all_objectives'],
        resulting_projection={'lifecycle': 'completed'}, audit_event='campaign.completed',
    ),
    _contract(
        'detection.publish', 'detection_revision', 'Publish a validated detection revision',
        ['validated'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['detection_publisher'],
        gates=[GateType.VALIDATION, GateType.PUBLICATION], evidence=['passed_detection_validation'],
        resulting_projection={'lifecycle': 'published'}, audit_event='detection.published',
    ),
    _contract(
        'investigation.close', 'investigation_case', 'Close an investigation with governed closure proof',
        ['investigating', 'decided'], [ActorLayer.GOVERN], ['manager', 'admin', 'owner'],
        responsibilities=['soc_closure_approver'],
        gates=[GateType.CLOSURE, GateType.EVIDENCE], evidence=['response_evidence', 'closure_proof'],
        sod=['actor_must_not_be_request_proposer'],
        resulting_projection={'lifecycle': 'closed'}, audit_event='investigation.closed',
    ),
    _contract(
        'assurance.obligation.satisfy', 'assurance_obligation', 'Satisfy an active assurance obligation',
        ['open', 'due', 'overdue'], [ActorLayer.GOVERN, ActorLayer.ASSURE], ['manager', 'admin', 'owner'],
        responsibilities=['assurance_owner'],
        gates=[GateType.EVIDENCE], evidence=['satisfaction_proof'], time_aware=True,
        resulting_projection={'lifecycle': 'satisfied'}, audit_event='assurance.obligation.satisfied',
    ),
    _contract(
        'integration.live_accept', 'integration', 'Accept a tested connector for live use',
        ['tested'], [ActorLayer.GOVERN, ActorLayer.ASSURE], ['admin', 'owner'],
        responsibilities=['integration_acceptor'],
        gates=[GateType.LIVE_ACCEPTANCE, GateType.EVIDENCE], evidence=['vendor_ack', 'acceptance_test_evidence'],
        time_aware=True, resulting_projection={'lifecycle': 'live_accepted'}, audit_event='integration.live_accepted',
    ),
)

ACTION_CONTRACTS: dict[str, ActionContract] = {item.action_id: item for item in _ACTIONS}
if len(ACTION_CONTRACTS) != len(_ACTIONS):
    raise RuntimeError('AGOM action ids must be globally unique.')


def list_action_contracts() -> list[ActionContract]:
    return [ACTION_CONTRACTS[key] for key in sorted(ACTION_CONTRACTS)]


def get_action_contract(action_id: str) -> ActionContract | None:
    return ACTION_CONTRACTS.get(str(action_id or '').strip())


def _gate_map(gate_results: Iterable[GateResult]) -> dict[GateType, GateResult]:
    return {item.gate: item for item in gate_results}


def evaluate_action(
    contract: ActionContract,
    *,
    current_state: str,
    actor_role: str,
    actor_layer: ActorLayer,
    actor_responsibilities: Iterable[str] = (),
    evidence_ready: bool,
    sod_eligible: bool,
    gate_results: Iterable[GateResult] = (),
) -> CapabilityItem:
    normalized_role = str(actor_role or '').strip().lower()
    if normalized_role not in {role.lower() for role in contract.allowed_roles} or actor_layer not in contract.actor_layers:
        return CapabilityItem(
            action_id=contract.action_id,
            mode=ActionMode.HIDDEN,
            intent=contract.intent,
            reason_code='ACTOR_NOT_ELIGIBLE',
            reason='Actor membership role/layer is not eligible for this governed action.',
        )

    actor_responsibility_set = {str(item).strip() for item in actor_responsibilities if str(item).strip()}
    missing_responsibilities = sorted(set(contract.required_responsibilities) - actor_responsibility_set)
    if missing_responsibilities:
        return CapabilityItem(
            action_id=contract.action_id,
            mode=ActionMode.HIDDEN,
            intent=contract.intent,
            reason_code='RESPONSIBILITY_NOT_ASSIGNED',
            reason='Actor does not hold the governed responsibility required for this action.',
            missing_requirements=missing_responsibilities,
        )

    if current_state not in contract.allowed_states:
        return CapabilityItem(
            action_id=contract.action_id,
            mode=ActionMode.BLOCKED,
            intent=contract.intent,
            reason_code='STATE_PRECONDITION_UNMET',
            reason='Entity lifecycle state does not satisfy the action precondition.',
            missing_requirements=[f'state in {contract.allowed_states}'],
        )

    if contract.sod_rules and not sod_eligible:
        return CapabilityItem(
            action_id=contract.action_id,
            mode=ActionMode.BLOCKED,
            intent=contract.intent,
            reason_code='SOD_VIOLATION',
            reason='Separation-of-duties policy prevents this actor from executing the action.',
            missing_requirements=list(contract.sod_rules),
        )

    supplied = _gate_map(gate_results)
    if contract.evidence_requirements and not evidence_ready:
        diagnostic_results: list[GateResult] = []
        diagnostic_missing = list(contract.evidence_requirements)
        evidence_gate = supplied.get(GateType.EVIDENCE)
        if evidence_gate is not None and evidence_gate.state is not GateState.PASS:
            diagnostic_results.append(evidence_gate)
            diagnostic_missing.extend(evidence_gate.missing_requirements)
        # Keep the canonical evidence requirements while preserving more precise
        # adapter-derived blockers. This remains fail-closed and gives the UI an
        # actionable reason without allowing a supplied PASS gate to override
        # the authoritative evidence_ready boolean.
        return CapabilityItem(
            action_id=contract.action_id,
            mode=ActionMode.BLOCKED,
            intent=contract.intent,
            reason_code='EVIDENCE_NOT_READY',
            reason='Required governed evidence is incomplete or not qualified.',
            missing_requirements=list(dict.fromkeys(diagnostic_missing)),
            gate_results=diagnostic_results,
        )

    required_results: list[GateResult] = []
    missing_gates: list[str] = []
    for gate in contract.required_gates:
        result = supplied.get(gate)
        if result is None:
            missing_gates.append(gate.value)
            continue
        required_results.append(result)
        if result.state is not GateState.PASS:
            missing_gates.append(f'{gate.value}:{result.state.value}')

    if missing_gates:
        return CapabilityItem(
            action_id=contract.action_id,
            mode=ActionMode.BLOCKED,
            intent=contract.intent,
            reason_code='GATE_NOT_SATISFIED',
            reason='One or more required governance gates are not satisfied.',
            missing_requirements=missing_gates,
            gate_results=required_results,
        )

    return CapabilityItem(
        action_id=contract.action_id,
        mode=ActionMode.ENABLED,
        intent=contract.intent,
        gate_results=required_results,
    )


def build_manifest(
    *,
    entity: EntityRef,
    projection: ProjectionSnapshot,
    actor_role: str,
    actor_layer: ActorLayer,
    actor_responsibilities: set[str] | None = None,
    evidence_ready_actions: set[str] | None = None,
    sod_eligible_actions: set[str] | None = None,
    gate_results_by_action: dict[str, list[GateResult]] | None = None,
) -> CapabilityManifest:
    actor_responsibilities = actor_responsibilities or set()
    evidence_ready_actions = evidence_ready_actions or set()
    sod_eligible_actions = sod_eligible_actions or set()
    gate_results_by_action = gate_results_by_action or {}
    lifecycle = projection.lifecycle or ''
    applicable = [item for item in _ACTIONS if item.entity_type == entity.entity_type]
    capabilities = [
        evaluate_action(
            item,
            current_state=lifecycle,
            actor_role=actor_role,
            actor_layer=actor_layer,
            actor_responsibilities=actor_responsibilities,
            evidence_ready=item.action_id in evidence_ready_actions or not item.evidence_requirements,
            sod_eligible=item.action_id in sod_eligible_actions or not item.sod_rules,
            gate_results=gate_results_by_action.get(item.action_id, []),
        )
        for item in applicable
    ]
    return CapabilityManifest(
        entity=entity,
        projection=projection,
        actor_layer=actor_layer,
        actor_role=actor_role,
        actor_responsibilities=sorted(actor_responsibilities),
        capabilities=capabilities,
        generated_at=datetime.now(timezone.utc),
    )


def registry_summary() -> dict[str, object]:
    contracts = list_action_contracts()
    return {
        'contract_version': AGOM_CONTRACT_VERSION,
        'policy_version': _POLICY_VERSION,
        'action_count': len(contracts),
        'entity_types': sorted({item.entity_type for item in contracts}),
        'gate_types': [item.value for item in GateType],
        'actor_layers': [item.value for item in ActorLayer],
        'actions': [item.model_dump(mode='json') for item in contracts],
    }
