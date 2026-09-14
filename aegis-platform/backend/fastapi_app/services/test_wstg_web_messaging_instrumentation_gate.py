from __future__ import annotations

from fastapi_app.services.wstg_capability_mapping import EXPECTED_GAPS, WSTGCapabilityMapping
from fastapi_app.services.wstg_catalog import WSTGCatalog
from fastapi_app.services.wstg_execution_planner import WSTGExecutionPlanner, WSTGPlanningContext


def test_web_messaging_instrumentation_does_not_cut_over_methodology():
    catalog = WSTGCatalog()
    test = catalog.resolve('WSTG-v42-CLNT-11')
    assert test.classification == 'GAP_NATIVE_SMALL'
    assert EXPECTED_GAPS[test.id] == 'browser.postmessage-instrumentation'

    requirement = WSTGCapabilityMapping().resolve(test.id)[0]
    assert requirement.id == 'web.clnt.web-messaging'
    assert requirement.availability == 'planned_native'
    assert [
        (binding.kind, binding.ref) for binding in requirement.provider_bindings
    ] == [
        ('registry_capability', 'browser.spa-discovery'),
        ('planned_native', 'browser.postmessage-instrumentation'),
    ]


def test_web_messaging_planner_remains_blocked_until_cutover_review():
    planner = WSTGExecutionPlanner()
    context = WSTGPlanningContext(
        asset_ref='asset-clnt11-instrumentation',
        authorization_ref='authorization-clnt11-instrumentation',
        asset_type='website',
        evidence_refs=(
            'asset:asset-clnt11-instrumentation',
            'authorization:authorization-clnt11-instrumentation',
        ),
    )
    plan = planner.plan(context, 'comprehensive')
    item = next(row for row in plan.items if row.wstg_id == 'WSTG-v42-CLNT-11')

    assert item.classification == 'GAP_NATIVE_SMALL'
    assert item.status == 'blocked'
    assert item.provider_capability_ids == ()
    assert item.authorization_required is True
    assert 'blocked until reviewed canonical integration' in item.reason
