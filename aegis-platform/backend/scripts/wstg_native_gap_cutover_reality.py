"""Independent A8 methodology cutover proof for the five approved WSTG native gaps.

Runtime implementation remains owned by Chat B. This A-side gate consumes the
authoritative registry/service surfaces and proves the reviewed methodology mapping,
planner and evidence-lineage cutover without granting pass/fail or finding authority.
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.wstg_capability_mapping import (
    CUTOVER_PROVIDER_ANCHORS,
    EXPECTED_GAPS,
    WSTGCapabilityMapping,
)
from fastapi_app.services.wstg_catalog import WSTGCatalog
from fastapi_app.services.wstg_execution_planner import WSTGExecutionPlanner, WSTGPlanningContext
from fastapi_app.services.wstg_native_capabilities import WSTG_INTERNAL_IDS, normalize_wstg_internal_output
from fastapi_app.services.wstg_observation_lineage import wstg_observation_lineage


EXPECTED_CLASSIFICATIONS = {
    'AUTO_EXISTING': 25,
    'ASSISTED_EXISTING': 45,
    'MANUAL_GOVERNED': 21,
    'GAP_NATIVE_SMALL': 5,
    'CONDITIONAL_NA': 1,
}


def _assert_internal_evidence_only(capability_id: str, short_wstg_id: str) -> None:
    raw = json.dumps({
        'observations': [{
            'capability_id': capability_id,
            'wstg_id': 'forged',
            'observation_only': False,
            'final_decision': True,
            'attacker_controlled': True,
        }]
    })
    normalized = normalize_wstg_internal_output(capability_id, raw)
    if normalized.get('count') != 1:
        raise ValueError(f'{capability_id} did not normalize exactly one bounded observation')
    row = normalized['observations'][0]
    if row.get('wstg_id') != short_wstg_id:
        raise ValueError(f'{capability_id} normalized WSTG identity drifted')
    if row.get('observation_only') is not True or row.get('final_decision') is not False:
        raise ValueError(f'{capability_id} escaped observation-only semantics')


def verify() -> dict:
    catalog = WSTGCatalog()
    mapping = WSTGCapabilityMapping()
    planner = WSTGExecutionPlanner()

    classifications = Counter(item.classification for item in catalog.tests)
    if dict(classifications) != EXPECTED_CLASSIFICATIONS:
        raise ValueError('Approved 97-test classification baseline changed')

    gap_ids = {item.id for item in catalog.tests if item.classification == 'GAP_NATIVE_SMALL'}
    if gap_ids != set(EXPECTED_GAPS) or gap_ids != set(CUTOVER_PROVIDER_ANCHORS):
        raise ValueError('Approved native-gap identity set changed')

    context = WSTGPlanningContext(
        asset_ref='a8-methodology-cutover-asset',
        authorization_ref='a8-methodology-cutover-authorization',
        asset_type='website',
        evidence_refs=(
            'asset:a8-methodology-cutover-asset',
            'authorization:a8-methodology-cutover-authorization',
        ),
    )
    plan = planner.plan(context, 'comprehensive')
    plan_by_id = {item.wstg_id: item for item in plan.items}

    short_ids = {
        'WSTG-v42-CONF-06': 'WSTG-CONF-06',
        'WSTG-v42-INPV-04': 'WSTG-INPV-04',
        'WSTG-v42-INPV-19': 'WSTG-INPV-19',
        'WSTG-v42-CRYP-01': 'WSTG-CRYP-01',
    }
    details: dict[str, dict] = {}

    for wstg_id in sorted(gap_ids):
        requirement = mapping.resolve(wstg_id)[0]
        bindings = {(item.kind, item.ref) for item in requirement.provider_bindings}
        anchor = CUTOVER_PROVIDER_ANCHORS[wstg_id]

        if requirement.availability != 'existing':
            raise ValueError(f'{wstg_id} did not complete reviewed mapping cutover')
        if any(item.kind == 'planned_native' for item in requirement.provider_bindings):
            raise ValueError(f'{wstg_id} still exposes a planned-native provider')
        if anchor not in bindings:
            raise ValueError(f'{wstg_id} is missing its reviewed cutover provider')

        item = plan_by_id[wstg_id]
        if item.classification != 'GAP_NATIVE_SMALL' or item.status != 'planned':
            raise ValueError(f'{wstg_id} did not become a reviewed planned methodology item')
        if not item.authorization_required:
            raise ValueError(f'{wstg_id} lost execution authorization requirement')

        anchor_kind, anchor_ref = anchor
        if anchor_kind == 'registry_capability':
            if anchor_ref not in item.provider_capability_ids:
                raise ValueError(f'{wstg_id} reviewed registry provider is not execution-ready')
            get_capability(anchor_ref)
            lineage = wstg_observation_lineage(anchor_ref)
            rows = {row['wstg_id']: row for row in lineage['tests']}
            row = rows.get(wstg_id)
            if row is None:
                raise ValueError(f'{anchor_ref} lost trusted {wstg_id} lineage')
            if (
                row.get('classification') != 'GAP_NATIVE_SMALL'
                or row.get('evidence_role') != 'supporting_observation'
                or row.get('methodology_state') != 'observed'
                or row.get('completion_claim_allowed') is not False
                or lineage.get('completion_claim_allowed') is not False
            ):
                raise ValueError(f'{anchor_ref} methodology lineage escaped A8 cutover policy')
            if anchor_ref in WSTG_INTERNAL_IDS:
                _assert_internal_evidence_only(anchor_ref, short_ids[wstg_id])
        elif anchor_kind == 'control_plane_service':
            if anchor_ref not in item.support_service_refs:
                raise ValueError(f'{wstg_id} reviewed service provider is missing from the plan')
        else:
            raise ValueError(f'Unsupported A8 cutover provider kind: {anchor_kind}')

        details[wstg_id] = {
            'semantic_requirement_id': requirement.id,
            'design_gap_id': EXPECTED_GAPS[wstg_id],
            'cutover_anchor_kind': anchor_kind,
            'cutover_anchor_ref': anchor_ref,
            'planner_status': item.status,
            'provider_capability_ids': list(item.provider_capability_ids),
            'support_service_refs': list(item.support_service_refs),
            'completion_claim_supported': True,
            'completion_claim_mode': 'evidence_plus_governed_attestation',
            'observation_alone_completion_allowed': False,
        }

    browser = wstg_observation_lineage('browser.spa-discovery')
    clnt11 = {row['wstg_id']: row for row in browser['tests']}.get('WSTG-v42-CLNT-11')
    if clnt11 is None:
        raise ValueError('CLNT-11 lost trusted browser observation lineage')
    if (
        clnt11.get('methodology_state') != 'observed'
        or clnt11.get('evidence_role') != 'supporting_observation'
        or clnt11.get('completion_claim_allowed') is not False
    ):
        raise ValueError('CLNT-11 browser evidence escaped A8 governed cutover semantics')

    return {
        'schema': 'aegis.wstg-methodology-cutover.v1',
        'proof_scope': (
            'Reviewed A8 canonical methodology cutover for the exact five historical '
            'GAP_NATIVE_SMALL rows. Runtime ownership remains external to this gate; '
            'pass/fail, finding confirmation and closure remain governed.'
        ),
        'classification_counts': EXPECTED_CLASSIFICATIONS,
        'cutover_gap_ids': sorted(gap_ids),
        'gap_details': details,
        'completion_claim_supported': True,
        'completion_claim_supported_count': len(gap_ids),
        'observation_alone_completion_allowed': False,
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
