import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

FILES = Path(__file__).resolve().parents[1] / 'ansible/roles/vulnerability_incidents/files'
sys.path.insert(0, str(FILES))


class EvidenceTests(unittest.TestCase):
    def test_worker_allows_long_reasoning_gaps_without_changing_chat_timeout(self):
        unit = (FILES / 'zag-ops-worker.service').read_text()
        self.assertIn('Environment=HERMES_CODEX_EVENT_STALE_TIMEOUT_SECONDS=180', unit)
        continuation = (FILES / 'zig-investigation-replies.service').read_text()
        self.assertIn('Environment=HERMES_CODEX_EVENT_STALE_TIMEOUT_SECONDS=180', continuation)

    def test_worker_retains_evidence_without_importing_conversation_style(self):
        worker = (FILES / 'zag_ops_worker.py').read_text()
        self.assertNotIn('writing-style.md', worker)
        self.assertIn('These fields are retained evidence for Zig, not user-facing prose.', worker)

    def test_replacement_projection_preserves_both_artifact_hashes_and_verdict(self):
        import investigation_evidence as evidence
        comparison = {'status': 'same_executable', 'verified_fix': False, 'deployment_exposure': 'not_assessed'}
        hashes = {'baseline': 'a'*64, 'candidate': 'a'*64}
        candidate = {'manifest_digest': 'sha256:'+'b'*64, 'repository': 'docker.io/library/caddy'}
        receipt = {'status': 'success', 'observation_id': 'proof', 'result': {
            'baseline': {'modules': [{'path': 'x'*100} for _ in range(200)]},
            'candidate': {'modules': [{'path': 'x'*100} for _ in range(200)]},
            'comparison': comparison, 'artifact_sha256': hashes, 'candidate_identity': candidate}}
        packed = evidence.pack({'ok': True, 'result': {'operation': 'verify_replacement', 'result': receipt}})
        projected = json.loads(packed)['data']['result']['result']['result']
        self.assertEqual(projected['comparison'], comparison)
        self.assertEqual(projected['artifact_sha256'], hashes)
        self.assertEqual(projected['candidate_identity'], candidate)
        self.assertLessEqual(len(packed.encode()), 4000)

    def test_nested_receipt_keeps_identity_and_matching_findings_with_omissions(self):
        import investigation_evidence as evidence
        receipt = {'observation_id': 'obs-one', 'timestamp': 1000, 'status': 'success',
                   'identity': {'host': 'pangolin'}, 'truncated': False,
                   'result': {'requirements': [{'description': '界' * 1000} for _ in range(8)],
                              'matching_findings': [{'id': 'CVE-2026-2303', 'severity': 'MEDIUM'}],
                              'status': 'complete', 'snapshot': {'sequence': 3, 'sha256': 'a' * 64}}}
        packed = evidence.pack({'ok': True, 'result': {'operation': 'deployment_coverage', 'result': receipt}}, 4000)
        result = json.loads(packed)
        projected = result['data']['result']['result']
        self.assertEqual(projected['observation_id'], 'obs-one')
        self.assertEqual(projected['identity'], {'host': 'pangolin'})
        self.assertEqual(projected['result']['matching_findings'], receipt['result']['matching_findings'])
        self.assertEqual(projected['result']['snapshot']['sequence'], 3)
        self.assertGreater(result['omitted']['/result/result/result/requirements'], 0)
        self.assertLessEqual(len(packed.encode()), 4000)

    def test_nested_projection_respects_small_byte_budgets_and_escapes_omission_paths(self):
        import investigation_evidence as evidence
        for limit in (256, 512, 1000, 4000):
            for value in ({'result': {'a/b~c': '界'*3000, 'status': 'unknown'}},
                          {str(i): {'payload': 'x'*500} for i in range(80)},
                          {'items': [{'x': '界'*10} for _ in range(100)]}):
                with self.subTest(limit=limit, value_type=list(value)):
                    output = evidence.pack(value, limit)
                    self.assertLessEqual(len(output.encode()), limit)
                    self.assertTrue(json.loads(output)['omitted'])
        result = json.loads(evidence.pack({'result': {'a/b~c': '界'*1000, 'status': 'unknown'}}, 1000))
        self.assertTrue(result['omitted']['/result/a~1b~0c'])
        self.assertEqual(result['data']['result']['status'], 'unknown')
        self.assertEqual(len(result['sha256']), 64)

    def test_provider_adapter_does_not_enforce_output_token_limits(self):
        import zag_model_proxy as proxy
        payload = proxy.prepare_payload({'model': 'gpt-5.6-sol', 'max_output_tokens': 4096,
                                         'max_tokens': 4096, 'max_completion_tokens': 4096})
        self.assertFalse(any(k.startswith('max_') for k in payload))
        self.assertFalse(payload['store'])
        self.assertTrue(payload['stream'])

    def test_duplicate_evidence_returns_a_reference_and_budget_denial_returns_no_data(self):
        import investigation_evidence as evidence
        calls = []
        budget = evidence.EvidenceBudget(lambda kind, amount: calls.append((kind, amount)))
        first = json.loads(budget.present({'value': 'private evidence'}))
        second = json.loads(budget.present({'value': 'private evidence'}))
        self.assertEqual(second['reference'], first['sha256'])
        self.assertNotIn('data', second)
        self.assertTrue(all(kind == 'evidence' for kind, _ in calls))
        def denied(*args):
            raise ValueError('budget exhausted')
        result = evidence.EvidenceBudget(denied).present({'value': 'private evidence'})
        self.assertNotIn('private evidence', result)
        self.assertEqual(json.loads(result)['status'], 'budget_exhausted')

    def test_tool_limit_denies_execution_before_the_remote_read(self):
        import investigation_evidence as evidence
        import zag_ops_worker as worker
        def denied(*args):
            raise ValueError('budget exhausted')
        with mock.patch.object(worker.subprocess, 'run') as run:
            output = worker.evidence_tool({'target': 'caddy', 'operation': 'service_state'}, evidence.EvidenceBudget(denied))
            run.assert_not_called()
            self.assertEqual(json.loads(output)['status'], 'budget_exhausted')

    def test_exhausted_evidence_denies_remote_read_with_tool_calls_remaining(self):
        import investigation_evidence as evidence
        import zag_ops_worker as worker
        def authorize(kind, amount):
            if kind == 'evidence':
                raise ValueError('evidence exhausted')
        with mock.patch.object(worker.subprocess, 'run') as run:
            output = worker.evidence_tool({'target': 'caddy', 'operation': 'service_state'}, evidence.EvidenceBudget(authorize))
            run.assert_not_called()
            self.assertEqual(json.loads(output)['status'], 'budget_exhausted')

    def test_idle_worker_exits_without_spending_job_lifetime_waiting(self):
        import zag_ops_worker as worker
        with mock.patch.object(sys, 'argv', ['worker']), mock.patch.dict(worker.os.environ, {'CREDENTIALS_DIRECTORY': '/unused'}, clear=True), \
             mock.patch.object(worker.Path, 'read_text', return_value='{}'), \
             mock.patch.object(worker, 'IncidentClient') as client, \
             mock.patch.object(worker.time, 'sleep', side_effect=AssertionError('idle lifetime consumed')):
            client.return_value.call.return_value = {'job': None}
            worker.main()
            client.return_value.call.assert_called_once_with('claim')

    def test_tool_output_is_projected_not_broken_by_character_slicing(self):
        import investigation_evidence as evidence
        import zag_ops_worker as worker
        calls = []
        budget = evidence.EvidenceBudget(lambda kind, amount: calls.append((kind, amount)))
        result = mock.Mock(returncode=0, stdout=json.dumps({'status': 'unknown', 'data': 'x' * 15000}))
        with mock.patch.object(worker.subprocess, 'run', return_value=result):
            output = worker.evidence_tool({'target': 'caddy', 'operation': 'service_state'}, budget)
        parsed = json.loads(output)
        self.assertEqual(parsed['data']['status'], 'unknown')
        self.assertTrue(parsed['omitted'])
        self.assertLessEqual(len(output.encode()), 4000)
        self.assertEqual(calls[0], ('tool', 1))
        self.assertEqual(calls[1:], [('evidence', 4000)])

    def test_failed_remote_read_keeps_its_prepaid_evidence_allowance(self):
        import investigation_evidence as evidence
        calls = []
        def failed_read():
            self.assertEqual(calls, [('tool', 1), ('evidence', 4000)])
            raise OSError('unreachable')
        output = evidence.EvidenceBudget(lambda *args: calls.append(args)).read(failed_read)
        self.assertEqual(json.loads(output)['data']['status'], 'unavailable')
        self.assertEqual(calls, [('tool', 1), ('evidence', 4000)])

    def test_failed_container_lookup_survives_the_evidence_wrapper(self):
        import investigation_evidence as evidence
        import zag_ops_worker as worker
        failure = {'code':'runtime_lookup_failed', 'runtime':'docker',
                   'lookup':{'stage':'inspect', 'argv':['docker','inspect','container']}}
        command = mock.Mock(returncode=1, stdout=json.dumps({'ok':False, 'error':'lookup failed', 'failure':failure}))
        with mock.patch.object(worker.subprocess, 'run', return_value=command):
            output = worker.evidence_tool({'target':'nerocd','operation':'container_metadata',
                                          'arguments':{'container':'app'}}, evidence.EvidenceBudget(lambda *_: None))
        result = json.loads(output)['data']
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['failure'], failure)
