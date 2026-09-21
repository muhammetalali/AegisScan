from pathlib import Path
import shutil
import tempfile
import unittest

from fastapi_app.services.wstg_execution_planner import (
    WSTGExecutionPlanner,
    WSTGPlanningContext,
)
from fastapi_app.services.wstg_catalog import PACK


class WSTGApplicabilityPlannerTests(unittest.TestCase):
    def setUp(self):
        self.planner = WSTGExecutionPlanner()

    def _website(self, **overrides):
        values = {
            'asset_ref': 'asset-real-contract',
            'authorization_ref': 'authorization-real-contract',
            'asset_type': 'website',
            'facts': (),
            'evidence_refs': ('asset:asset-real-contract', 'authorization:authorization-real-contract'),
        }
        values.update(overrides)
        return WSTGPlanningContext(**values)

    def test_plans_exact_canonical_97_without_terminal_verdicts(self):
        result = self.planner.plan(self._website(), 'comprehensive')
        self.assertEqual(len(result.items), 97)
        self.assertEqual({item.wstg_id for item in result.items}, {item.id for item in self.planner.catalog.tests})
        self.assertFalse(
            {item.status for item in result.items}
            & {'not_started', 'queued', 'running', 'passed', 'failed', 'error'}
        )
        self.assertEqual(
            sum(item.status == 'manual_required' for item in result.items),
            21,
        )
        gap_ids = {
            item.id for item in self.planner.catalog.tests
            if item.classification == 'GAP_NATIVE_SMALL'
        }
        self.assertTrue(gap_ids)
        gap_items = [item for item in result.items if item.wstg_id in gap_ids]
        self.assertEqual({item.wstg_id for item in gap_items}, gap_ids)
        self.assertTrue(all(item.status == 'planned' for item in gap_items))
        self.assertTrue(all(item.provider_capability_ids or item.support_service_refs for item in gap_items))

    def test_conditional_flash_test_fails_closed_without_authoritative_fact(self):
        result = self.planner.plan(self._website(), 'comprehensive')
        item = next(x for x in result.items if x.wstg_id == 'WSTG-v42-CLNT-08')
        self.assertEqual(item.status, 'inconclusive')
        self.assertEqual(item.provider_capability_ids, ())

    def test_conditional_flash_positive_fact_plans_existing_provider(self):
        context = self._website(
            facts=('technology.flash.present',),
            evidence_refs=(
                'asset:asset-real-contract',
                'authorization:authorization-real-contract',
                'technology:flash-fingerprint',
            ),
        )
        result = self.planner.plan(context, 'comprehensive')
        item = next(x for x in result.items if x.wstg_id == 'WSTG-v42-CLNT-08')
        self.assertEqual(item.status, 'planned')
        self.assertIn('browser.spa-discovery', item.provider_capability_ids)
        self.assertTrue(item.authorization_required)

    def test_conditional_negative_requires_evidence_and_produces_reasoned_na(self):
        context = self._website(
            facts=('technology.flash.absence_attested',),
            evidence_refs=('evidence:flash-absence-attestation',),
        )
        result = self.planner.plan(context, 'comprehensive')
        item = next(x for x in result.items if x.wstg_id == 'WSTG-v42-CLNT-08')
        self.assertEqual(item.status, 'not_applicable')
        self.assertEqual(item.applicability_evidence_refs, ('evidence:flash-absence-attestation',))
        self.assertFalse(item.authorization_required)
        self.assertIn('attests', item.reason)

    def test_conflicting_conditional_facts_never_dispatch(self):
        context = self._website(
            facts=('technology.flash.present', 'technology.flash.absence_attested'),
            evidence_refs=('evidence:one', 'evidence:two'),
        )
        result = self.planner.plan(context, 'comprehensive')
        item = next(x for x in result.items if x.wstg_id == 'WSTG-v42-CLNT-08')
        self.assertEqual(item.status, 'inconclusive')
        self.assertEqual(item.provider_capability_ids, ())

    def test_non_web_asset_is_reasoned_not_applicable_for_all_97(self):
        context = WSTGPlanningContext(
            asset_ref='asset-source-code',
            authorization_ref='authorization-source-code',
            asset_type='source_code',
            evidence_refs=('asset:asset-source-code',),
        )
        result = self.planner.plan(context, 'comprehensive')
        self.assertEqual(result.status_counts, {'not_applicable': 97})
        self.assertTrue(all(item.applicability_evidence_refs == ('asset-source-code',) for item in result.items))

    def test_planner_requires_authoritative_asset_and_authorization_binding(self):
        with self.assertRaisesRegex(ValueError, 'authorization_ref'):
            WSTGPlanningContext(
                asset_ref='asset-1',
                authorization_ref='',
                asset_type='website',
            )
        with self.assertRaisesRegex(ValueError, 'asset_ref'):
            WSTGPlanningContext(
                asset_ref='',
                authorization_ref='auth-1',
                asset_type='website',
            )

    def test_public_wstg_plan_exposes_capability_ids_not_tool_or_command_keys(self):
        result = self.planner.plan(self._website(), 'standard').public_dict()

        def keys(value):
            if isinstance(value, dict):
                for key, nested in value.items():
                    yield key
                    yield from keys(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from keys(nested)

        all_keys = set(keys(result))
        self.assertFalse({'tool', 'binary', 'command', 'argv', 'shell', 'authorized'} & all_keys)

    def test_policy_pack_is_exact_97_and_bound_to_catalog_classification(self):
        self.assertEqual(len(self.planner.policies), 97)
        self.assertEqual(
            {item.wstg_id: item.mode for item in self.planner.policies},
            {item.id: item.classification for item in self.planner.catalog.tests},
        )
        sample = self.planner._policies['WSTG-v42-INFO-02']
        self.assertEqual(sample.runner_preference, 'kali-recon-web')
        self.assertEqual(sample.kali_requirement, 'required')

    def test_policy_checksum_tamper_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pack = Path(tmp) / 'pack'
            shutil.copytree(PACK, pack)
            with (pack / 'execution_policies.json').open('a', encoding='utf-8') as handle:
                handle.write(' ')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                WSTGExecutionPlanner(pack)

    def test_policy_fingerprint_is_deterministic_and_context_bound(self):
        first = self.planner.plan(self._website(), 'standard')
        second = self.planner.plan(self._website(), 'standard')
        self.assertEqual(first.policy_fingerprint, second.policy_fingerprint)
        flash = self.planner.plan(
            self._website(
                facts=('technology.flash.present',),
                evidence_refs=('technology:flash',),
            ),
            'standard',
        )
        self.assertNotEqual(first.policy_fingerprint, flash.policy_fingerprint)


if __name__ == '__main__':
    unittest.main()
