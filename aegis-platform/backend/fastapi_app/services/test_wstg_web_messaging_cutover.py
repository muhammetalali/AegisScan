from __future__ import annotations

from fastapi_app.services.wstg_capability_mapping import (
    EXPECTED_GAPS,
    WSTGCapabilityMapping,
)
from fastapi_app.services.wstg_catalog import WSTGCatalog
from fastapi_app.services.wstg_observation_lineage import wstg_observation_lineage


def test_web_messaging_is_existing_assisted_capability_not_native_gap():
    catalog = WSTGCatalog()
    test = catalog.resolve('WSTG-v42-CLNT-11')
    assert test.classification == 'ASSISTED_EXISTING'
    assert test.id not in EXPECTED_GAPS

    mapping = WSTGCapabilityMapping()
    requirements = mapping.resolve(test.id)
    assert len(requirements) == 1
    requirement = requirements[0]
    assert requirement.id == 'web.clnt.web-messaging'
    assert requirement.availability == 'existing'
    assert [
        (binding.kind, binding.ref) for binding in requirement.provider_bindings
    ] == [('registry_capability', 'browser.spa-discovery')]


def test_browser_spa_lineage_exposes_web_messaging_as_supporting_observation():
    lineage = wstg_observation_lineage('browser.spa-discovery')
    item = next(
        row for row in lineage['tests']
        if row['wstg_id'] == 'WSTG-v42-CLNT-11'
    )
    assert item['classification'] == 'ASSISTED_EXISTING'
    assert item['semantic_requirement_id'] == 'web.clnt.web-messaging'
    assert item['evidence_role'] == 'supporting_observation'
    assert item['methodology_state'] == 'observed'
    assert item['completion_claim_allowed'] is False
    assert lineage['claim_policy'] == 'observation-only'
    assert lineage['completion_claim_allowed'] is False
