from __future__ import annotations

from fastapi_app.services.wstg_capability_mapping import EXPECTED_GAPS, WSTGCapabilityMapping
from fastapi_app.services.wstg_catalog import WSTGCatalog
from fastapi_app.services.wstg_execution_planner import WSTGExecutionPlanner, WSTGPlanningContext


def test_web_messaging_instrumentation_is_cut_over_without_native_gap():
    catalog = WSTGCatalog()
    test = catalog.resolve('WSTG-v42-CLNT-11')
    assert test.classification == 'ASSISTED_EXISTING'
    assert test.id not in EXPECTED_GAPS

    requirement = WSTGCapabilityMapping().resolve(test.id)[0]
    assert requirement.id == 'web.clnt.web-messaging'
    assert requirement.availability == 'existing'
    assert [
        (binding.kind, binding.ref) for binding in requirement.provider_bindings
    ] == [('registry_capability', 'browser.spa-discovery')]


def test_web_messaging_planner_uses_reviewed_browser_capability_after_cutover():
    planner = WSTGExecutionPlanner()
    context = WSTGPlanningContext(
        asset_ref='asset-clnt11-cutover',
        authorization_ref='authorization-clnt11-cutover',
        asset_type='website',
        evidence_refs=(
            'asset:asset-clnt11-cutover',
            'authorization:authorization-clnt11-cutover',
        ),
    )
    plan = planner.plan(context, 'comprehensive')
    item = next(row for row in plan.items if row.wstg_id == 'WSTG-v42-CLNT-11')

    assert item.classification == 'ASSISTED_EXISTING'
    assert item.status == 'planned'
    assert item.provider_capability_ids == ('browser.spa-discovery',)
    assert item.authorization_required is True
