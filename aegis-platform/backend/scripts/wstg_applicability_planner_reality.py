"""Independent exact-head proof for WSTG applicability and execution planning."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.wstg_execution_planner import (
    WSTGExecutionPlanner,
    WSTGPlanningContext,
)
from fastapi_app.services.wstg_catalog import PACK


def _digest(name: str) -> str:
    return hashlib.sha256((PACK / name).read_bytes()).hexdigest()


def verify() -> dict:
    planner = WSTGExecutionPlanner()

    website = WSTGPlanningContext(
        asset_ref='reality-website-asset',
        authorization_ref='reality-authorization',
        asset_type='website',
        evidence_refs=('asset:reality-website-asset', 'authorization:reality-authorization'),
    )
    website_plan = planner.plan(website, 'comprehensive')
    if len(website_plan.items) != 97:
        raise ValueError('Website WSTG plan does not cover all 97 official tests')
    if any(item.status in {'passed', 'failed', 'queued', 'running', 'error'} for item in website_plan.items):
        raise ValueError('Planner emitted execution/verdict state instead of planning state')

    manual = [
        item for item in website_plan.items
        if item.classification == 'MANUAL_GOVERNED'
    ]
    if len(manual) != 21 or any(item.status != 'manual_required' for item in manual):
        raise ValueError('Manual governed WSTG semantics changed')

    gaps = [
        item for item in website_plan.items
        if item.classification == 'GAP_NATIVE_SMALL'
    ]
    if len(gaps) != 5 or any(item.status != 'planned' for item in gaps):
        raise ValueError('Reviewed native-gap cutovers must be planned through current providers')
    if any(not (item.provider_capability_ids or item.support_service_refs) for item in gaps):
        raise ValueError('Reviewed native-gap cutover lost its execution-ready provider/service')
    if any(not item.authorization_required for item in gaps):
        raise ValueError('Reviewed native-gap cutover lost authorization requirement')

    conditional = next(
        item for item in website_plan.items
        if item.wstg_id == 'WSTG-v42-CLNT-08'
    )
    if conditional.status != 'inconclusive':
        raise ValueError('Conditional Flash applicability must fail closed without evidence')

    flash_context = WSTGPlanningContext(
        asset_ref='reality-website-asset',
        authorization_ref='reality-authorization',
        asset_type='website',
        facts=('technology.flash.present',),
        evidence_refs=('technology:reality-flash-fingerprint',),
    )
    flash_plan = planner.plan(flash_context, 'comprehensive')
    flash = next(item for item in flash_plan.items if item.wstg_id == 'WSTG-v42-CLNT-08')
    if flash.status != 'planned' or 'browser.spa-discovery' not in flash.provider_capability_ids:
        raise ValueError('Positive Flash evidence did not produce the expected bounded plan')

    non_web = WSTGPlanningContext(
        asset_ref='reality-source-asset',
        authorization_ref='reality-source-authorization',
        asset_type='source_code',
        evidence_refs=('asset:reality-source-asset',),
    )
    non_web_plan = planner.plan(non_web, 'comprehensive')
    if non_web_plan.status_counts != {'not_applicable': 97}:
        raise ValueError('Non-web asset applicability did not fail closed to reasoned N/A')

    try:
        WSTGPlanningContext(
            asset_ref='asset',
            authorization_ref='',
            asset_type='website',
        )
    except ValueError:
        pass
    else:
        raise ValueError('Planner accepted a context without authoritative authorization binding')

    public = website_plan.public_dict()
    forbidden_keys = {'tool', 'binary', 'command', 'argv', 'shell', 'authorized'}

    def walk(value):
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in forbidden_keys:
                    raise ValueError(f'Planner leaked forbidden execution authority field: {key}')
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(public)

    return {
        'proof_scope': (
            'WSTG applicability + semantic execution planning only; no scan creation, '
            'dispatch, security verdict, finding projection, or client authorization decision'
        ),
        'official_tests_planned': len(website_plan.items),
        'website_status_counts': dict(sorted(Counter(item.status for item in website_plan.items).items())),
        'non_web_status_counts': non_web_plan.status_counts,
        'manual_governed': len(manual),
        'reviewed_native_gap_cutovers_planned': [item.wstg_id for item in gaps],
        'native_gap_completion_claim_allowed': False,
        'conditional_without_evidence': conditional.status,
        'conditional_with_flash_evidence': flash.status,
        'website_policy_fingerprint': website_plan.policy_fingerprint,
        'flash_policy_fingerprint': flash_plan.policy_fingerprint,
        'planner_file_sha256': {
            'execution_policies.json': _digest('execution_policies.json'),
            'applicability.json': _digest('applicability.json'),
        },
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
