"""A retained conclusion needs scoped, presented evidence; it is not memory."""
import json
import unittest

from test_investigation_evidence import FILES
import investigation_evidence as evidence


class AssessmentTests(unittest.TestCase):
    def test_unknown_references_and_unscoped_exposure_are_visibility_gaps(self):
        budget = evidence.EvidenceBudget(lambda *args: None)
        ref = json.loads(budget.present({'status': 'observed'}))['sha256']
        claim = {'claim': 'Linux artifact', 'references': [ref], 'confidence': 'high',
                 'source': 'caddy', 'scope': 'proxy', 'classification': 'non_reachable', 'visibility_gap': ''}
        raw = json.dumps({'summary': 'Platform prerequisite absent.', 'next_step':'Recheck if the platform changes.', 'claims': [claim]})
        result = evidence.assessment(raw, budget, {'caddy': {'proxy'}})
        self.assertTrue(result['complete'])
        self.assertEqual(result['summary'],'Platform prerequisite absent.')
        self.assertEqual(result['next_step'],'Recheck if the platform changes.')
        self.assertEqual(result['journal'][0]['classification'], 'non_reachable')
        self.assertEqual(result['verification'], 'investigator_assessment_not_operator_verified')
        for changes in ({'references': ['x'*64]}, {'source': 'other'}, {'classification': 'safe'}):
            result = evidence.assessment(json.dumps({'summary': 'Safe', 'claims': [{**claim, **changes}]}), budget, {'caddy': {'proxy'}})
            self.assertFalse(result['complete'])
            self.assertEqual(result['classification'], 'visibility_gap')


if __name__ == '__main__':
    unittest.main()
