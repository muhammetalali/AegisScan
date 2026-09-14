from __future__ import annotations

import copy
import unittest

from .wstg_observation_lineage import (
    attach_wstg_evidence_metadata,
    attach_wstg_finding_lineage,
    wstg_observation_lineage,
)


class WSTGObservationLineageTests(unittest.TestCase):
    def test_nmap_lineage_is_canonical_deterministic_and_non_authoritative(self):
        first = wstg_observation_lineage('network.nmap')
        second = wstg_observation_lineage('network.nmap')
        self.assertEqual(first, second)
        self.assertEqual(first['schema'], 'aegis.wstg-observation-lineage.v1')
        self.assertEqual(first['methodology'], 'WSTG')
        self.assertEqual(first['methodology_version'], '4.2')
        self.assertEqual(first['claim_policy'], 'observation-only')
        self.assertFalse(first['completion_claim_allowed'])
        self.assertEqual(first['finding_state_authority'], 'governed-finding-confirmation')
        self.assertEqual(len(first['lineage_fingerprint']), 64)
        self.assertEqual(
            {item['wstg_id'] for item in first['tests']},
            {
                'WSTG-v42-INFO-02',
                'WSTG-v42-INFO-04',
                'WSTG-v42-INFO-10',
                'WSTG-v42-CONF-01',
                'WSTG-v42-CONF-05',
            },
        )
        self.assertTrue(all(item['completion_claim_allowed'] is False for item in first['tests']))

    def test_browser_lineage_preserves_manual_gap_and_conditional_fail_closed_semantics(self):
        payload = wstg_observation_lineage('browser.spa-discovery')
        rows = {item['wstg_id']: item for item in payload['tests']}

        manual = rows['WSTG-v42-IDNT-02']
        self.assertEqual(manual['classification'], 'MANUAL_GOVERNED')
        self.assertEqual(manual['evidence_role'], 'supporting_context')
        self.assertEqual(manual['methodology_state'], 'manual_required')
        self.assertFalse(manual['completion_claim_allowed'])

        gap = rows['WSTG-v42-CLNT-11']
        self.assertEqual(gap['classification'], 'GAP_NATIVE_SMALL')
        self.assertEqual(gap['methodology_state'], 'blocked_native_gap')
        self.assertFalse(gap['completion_claim_allowed'])

        conditional = rows['WSTG-v42-CLNT-08']
        self.assertEqual(conditional['classification'], 'CONDITIONAL_NA')
        self.assertEqual(conditional['evidence_role'], 'conditional_context')
        self.assertEqual(conditional['methodology_state'], 'inconclusive')
        self.assertFalse(conditional['completion_claim_allowed'])

    def test_registered_planned_native_gaps_emit_blocked_lineage_without_cutover(self):
        expected = {
            'web.http-method-policy': 'WSTG-v42-CONF-06',
            'web.duplicate-parameter-semantics': 'WSTG-v42-INPV-04',
            'web.ssrf-canary-validation': 'WSTG-v42-INPV-19',
            'tls.posture': 'WSTG-v42-CRYP-01',
        }
        for capability_id, wstg_id in expected.items():
            with self.subTest(capability_id=capability_id):
                payload = wstg_observation_lineage(capability_id)
                rows = {item['wstg_id']: item for item in payload['tests']}
                self.assertIn(wstg_id, rows)
                row = rows[wstg_id]
                self.assertEqual(row['classification'], 'GAP_NATIVE_SMALL')
                self.assertEqual(row['evidence_role'], 'supporting_context')
                self.assertEqual(row['methodology_state'], 'blocked_native_gap')
                self.assertFalse(row['completion_claim_allowed'])
                self.assertFalse(payload['completion_claim_allowed'])
                decorated = attach_wstg_evidence_metadata({'capability_id': capability_id}, capability_id)
                self.assertIn('wstg_lineage', decorated)
                self.assertFalse(decorated['wstg_lineage']['completion_claim_allowed'])

    def test_decorators_preserve_business_data_and_replace_reserved_lineage(self):
        metadata = {'target': 'https://example.test', 'exit_code': 0}
        raw_data = {'rule_id': 'source-rule', '_aegisscan_wstg': {'attacker_controlled': True}}
        metadata_before = copy.deepcopy(metadata)
        raw_before = copy.deepcopy(raw_data)

        decorated_metadata = attach_wstg_evidence_metadata(metadata, 'web.nuclei')
        decorated_raw = attach_wstg_finding_lineage(raw_data, 'web.nuclei')

        self.assertEqual(metadata, metadata_before)
        self.assertEqual(raw_data, raw_before)
        self.assertEqual(decorated_metadata['target'], 'https://example.test')
        self.assertIn('wstg_lineage', decorated_metadata)
        self.assertFalse(decorated_metadata['wstg_lineage']['completion_claim_allowed'])
        self.assertEqual(decorated_raw['rule_id'], 'source-rule')
        self.assertNotIn('attacker_controlled', decorated_raw['_aegisscan_wstg'])
        self.assertFalse(decorated_raw['_aegisscan_wstg']['completion_claim_allowed'])

    def test_unmapped_registered_capability_does_not_invent_wstg_coverage(self):
        payload = wstg_observation_lineage('binary.checksec')
        self.assertEqual(payload['tests'], [])
        self.assertFalse(payload['completion_claim_allowed'])
        self.assertNotIn('wstg_lineage', attach_wstg_evidence_metadata({'x': 1}, 'binary.checksec'))
        self.assertNotIn('_aegisscan_wstg', attach_wstg_finding_lineage({'x': 1}, 'binary.checksec'))


if __name__ == '__main__':
    unittest.main()
