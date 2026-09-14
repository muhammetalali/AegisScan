"""Independent cutover-safety proof for the five approved WSTG native gaps.

This gate intentionally does not make a gap executable or complete. It proves that
registered evidence-producing validators remain methodology-blocked until a separate
reviewed cutover changes the canonical catalog/mapping/planner contract.
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.capability_registry import get_capability
from fastapi_app.services.wstg_capability_mapping import EXPECTED_GAPS, WSTGCapabilityMapping
from fastapi_app.services.wstg_catalog import WSTGCatalog
from fastapi_app.services.wstg_execution_planner import WSTGExecutionPlanner, WSTGPlanningContext
from fastapi_app.services.wstg_native_capabilities import (
    WSTG_INTERNAL_IDS,
    normalize_wstg_internal_output,
)
from fastapi_app.services.wstg_observation_lineage import wstg_observation_lineage


EXPECTED_CLASSIFICATIONS = {
    'AUTO_EXISTING': 25,
    'ASSISTED_EXISTING': 45,
    'MANUAL_GOVERNED': 21,
    'GAP_NATIVE_SMALL': 5,
    'CONDITIONAL_NA': 1,
}


def _registered_capability(capability_id: str):
    try:
        return get_capability(capability_id)
    except ValueError:
        return None


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
        raise ValueError(f'{capability_id} evidence escaped observation-only semantics')


def verify() -> dict:
    catalog = WSTGCatalog()
    mapping = WSTGCapabilityMapping()
    planner = WSTGExecutionPlanner()

    classifications = Counter(item.classification for item in catalog.tests)
    if dict(classifications) != EXPECTED_CLASSIFICATIONS:
        raise ValueError(
            f'Approved 97-test classification changed: expected={EXPECTED_CLASSIFICATIONS} '
            f'actual={dict(classifications)}'
        )

    gap_ids = {item.id for item in catalog.tests if item.classification == 'GAP_NATIVE_SMALL'}
    if gap_ids != set(EXPECTED_GAPS):
        raise ValueError('Approved native-gap identity set changed')

    context = WSTGPlanningContext(
        asset_ref='native-gap-reality-asset',
        authorization_ref='native-gap-reality-authorization',
        asset_type='website',
        evidence_refs=(
            'asset:native-gap-reality-asset',
            'authorization:native-gap-reality-authorization',
        ),
    )
    plan = planner.plan(context, 'comprehensive')
    plan_by_id = {item.wstg_id: item for item in plan.items}

    details: dict[str, dict] = {}
    registered_gap_capabilities: list[str] = []

    short_ids = {
        'WSTG-v42-CONF-06': 'WSTG-CONF-06',
        'WSTG-v42-INPV-04': 'WSTG-INPV-04',
        'WSTG-v42-INPV-19': 'WSTG-INPV-19',
        'WSTG-v42-CRYP-01': 'WSTG-CRYP-01',
    }

    for wstg_id, planned_capability_id in EXPECTED_GAPS.items():
        canonical = catalog.resolve(wstg_id)
        requirement = mapping.resolve(wstg_id)[0]
        planned = [
            binding.ref
            for binding in requirement.provider_bindings
            if binding.kind == 'planned_native'
        ]
        if canonical.classification != 'GAP_NATIVE_SMALL':
            raise ValueError(f'{wstg_id} is no longer an approved native gap')
        if requirement.availability != 'planned_native' or planned != [planned_capability_id]:
            raise ValueError(f'{wstg_id} native-gap mapping changed before reviewed cutover')

        item = plan_by_id[wstg_id]
        if item.classification != 'GAP_NATIVE_SMALL':
            raise ValueError(f'{wstg_id} planner classification drifted')
        if item.status != 'blocked':
            raise ValueError(f'{wstg_id} planner became executable before reviewed cutover')
        if item.provider_capability_ids:
            raise ValueError(f'{wstg_id} planner exposed providers while the gap is blocked')
        if item.authorization_required is not True:
            raise ValueError(f'{wstg_id} lost its authorization requirement')

        capability = _registered_capability(planned_capability_id)
        registered = capability is not None
        lineage_tests: list[str] = []
        if registered:
            registered_gap_capabilities.append(planned_capability_id)
            lineage = wstg_observation_lineage(planned_capability_id)
            rows = {row['wstg_id']: row for row in lineage['tests']}
            row = rows.get(wstg_id)
            if row is None:
                raise ValueError(f'{planned_capability_id} evidence lacks trusted {wstg_id} lineage')
            if row.get('classification') != 'GAP_NATIVE_SMALL':
                raise ValueError(f'{planned_capability_id} evidence classification drifted')
            if row.get('methodology_state') != 'blocked_native_gap':
                raise ValueError(f'{planned_capability_id} evidence escaped blocked-native-gap state')
            if row.get('completion_claim_allowed') is not False:
                raise ValueError(f'{planned_capability_id} evidence incorrectly grants completion')
            if lineage.get('completion_claim_allowed') is not False:
                raise ValueError(f'{planned_capability_id} lineage incorrectly grants completion')
            lineage_tests = sorted(rows)

            if planned_capability_id in WSTG_INTERNAL_IDS:
                _assert_internal_evidence_only(
                    planned_capability_id,
                    short_ids[wstg_id],
                )

        details[wstg_id] = {
            'semantic_requirement_id': requirement.id,
            'planned_capability_id': planned_capability_id,
            'registered_in_capability_registry': registered,
            'planner_status': item.status,
            'planner_provider_capability_ids': list(item.provider_capability_ids),
            'completion_claim_allowed': False,
            'lineage_tests_when_registered': lineage_tests,
        }

    browser_lineage = wstg_observation_lineage('browser.spa-discovery')
    browser_rows = {row['wstg_id']: row for row in browser_lineage['tests']}
    clnt11 = browser_rows.get('WSTG-v42-CLNT-11')
    if clnt11 is None:
        raise ValueError('CLNT-11 browser instrumentation lost trusted supporting lineage')
    if (
        clnt11.get('classification') != 'GAP_NATIVE_SMALL'
        or clnt11.get('methodology_state') != 'blocked_native_gap'
        or clnt11.get('completion_claim_allowed') is not False
    ):
        raise ValueError('CLNT-11 browser telemetry was promoted beyond supporting blocked-gap evidence')

    return {
        'proof_scope': (
            'Five approved WSTG native gaps: canonical identity + planned-native mapping + '
            'planner blocking + observation-only evidence lineage. No dispatch, verdict, '
            'finding confirmation, closure, accepted-risk or methodology cutover authority.'
        ),
        'classification_counts': EXPECTED_CLASSIFICATIONS,
        'approved_gap_ids': sorted(EXPECTED_GAPS),
        'registered_gap_capabilities': sorted(registered_gap_capabilities),
        'gap_details': details,
        'clnt11_browser_instrumentation': {
            'capability_id': 'browser.spa-discovery',
            'methodology_state': clnt11['methodology_state'],
            'completion_claim_allowed': clnt11['completion_claim_allowed'],
        },
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
