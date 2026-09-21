from __future__ import annotations

from fastapi_app.services.wstg_capability_mapping import EXPECTED_GAPS, WSTGCapabilityMapping
from fastapi_app.services.wstg_catalog import WSTGCatalog
from fastapi_app.services.wstg_execution_planner import WSTGExecutionPlanner, WSTGPlanningContext


def test_web_messaging_reviewed_cutover_uses_browser_telemetry_and_semantic_service():
    catalog = WSTGCatalog()
    test = catalog.resolve('WSTG-v42-CLNT-11')
    assert test.classification == 'GAP_NATIVE_SMALL'
    assert EXPECTED_GAPS[test.id] == 'browser.postmessage-instrumentation'

    requirement = WSTGCapabilityMapping().resolve(test.id)[0]
    assert requirement.id == 'web.clnt.web-messaging'
    assert requirement.availability == 'existing'
    assert [
        (binding.kind, binding.ref) for binding in requirement.provider_bindings
    ] == [
        ('registry_capability', 'browser.spa-discovery'),
        ('control_plane_service', 'fastapi_app.services.web_messaging_semantics'),
    ]


def test_web_messaging_planner_uses_reviewed_cutover_without_granting_decision_authority():
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
    assert item.status == 'planned'
    assert 'browser.spa-discovery' in item.provider_capability_ids
    assert 'fastapi_app.services.web_messaging_semantics' in item.support_service_refs
    assert item.authorization_required is True
    assert 'Reviewed native-gap cutover provider is execution-ready' in item.reason
