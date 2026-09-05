import importlib.util
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / 'ansible/roles/update_monitor/files/homelab_defense.py'
SPEC = importlib.util.spec_from_file_location('defense_runner', SOURCE)
DEFENSE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEFENSE)


class DefenseRunnerTests(unittest.TestCase):
    def action(self):
        return {'deployment': 'fixture', 'kind': 'patch', 'enabled': True, 'protects_control_plane': False,
                'current_sha256': 'old', 'candidate_sha256': 'new', 'runtime_sha256': 'runtime',
                **{name: ['/test/' + name] for name in ('probe', 'apply', 'health', 'rollback', 'recovery_check')}}

    def receipt(self, action):
        return {**{k: action[k] for k in ('deployment', 'current_sha256', 'candidate_sha256', 'runtime_sha256')},
                'expires_at': 200, 'checks': {k: True for k in DEFENSE.PATCH_CHECKS | DEFENSE.EMERGENCY_CHECKS}}

    def test_missing_recovery_blocks_patch(self):
        action = self.action()
        receipt = self.receipt(action)
        receipt['checks']['tested_recovery'] = False
        result = DEFENSE.prepare({'schema': 1, 'enabled': True, 'actions': {'update': action}}, 'update', receipt,
                                 {'current_sha256': 'old', 'runtime_sha256': 'runtime'}, 100)
        self.assertFalse(result['eligible'])
        self.assertIn('missing verified check: tested_recovery', result['blockers'])

    def test_target_swap_stale_receipt_and_disabled_policy_block(self):
        action = self.action()
        receipt = self.receipt(action)
        receipt['deployment'] = 'another-service'
        result = DEFENSE.prepare({'schema': 1, 'enabled': False, 'actions': {'update': action}}, 'update', receipt,
                                 {'current_sha256': 'old', 'runtime_sha256': 'changed'}, 300)
        self.assertFalse(result['eligible'])
        for expected in ('action policy disabled', 'receipt binding mismatch: deployment', 'receipt missing or stale', 'live target changed since verification'):
            self.assertIn(expected, result['blockers'])

    def test_emergency_requires_bounded_expiry(self):
        action = {**self.action(), 'kind': 'emergency', 'ttl_seconds': 7200}
        result = DEFENSE.prepare({'schema': 1, 'enabled': True, 'actions': {'isolate': action}}, 'isolate', self.receipt(action),
                                 {'current_sha256': 'old', 'runtime_sha256': 'runtime'}, 100)
        self.assertFalse(result['eligible'])
        self.assertIn('emergency action requires an expiry within one hour', result['blockers'])

    def test_unknown_action_cannot_supply_its_own_handler(self):
        self.assertFalse(DEFENSE.prepare({'actions': {}}, 'shell', {}, {}, 100)['eligible'])

    def test_retry_cannot_reapply_an_expired_and_restored_emergency(self):
        action = {**self.action(), 'kind': 'emergency', 'ttl_seconds': 60}
        receipt = self.receipt(action)
        result = DEFENSE.prepare({'schema': 1, 'enabled': True, 'actions': {'isolate': action}},
                                 'isolate', receipt, {'current_sha256': 'old', 'runtime_sha256': 'runtime'},
                                 100, {DEFENSE.receipt_identity(receipt)})
        self.assertFalse(result['eligible'])
        self.assertIn('verification receipt already consumed; fresh verification required', result['blockers'])

    def test_health_failure_restores_actual_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, candidate, journal = root / 'current', root / 'candidate', root / 'journal.json'
            artifact.write_text('old')
            candidate.write_text('new')
            action = {**self.action(), 'artifact': str(artifact), 'candidate': str(candidate),
                      'current_sha256': DEFENSE.digest(str(artifact)), 'candidate_sha256': DEFENSE.digest(str(candidate))}
            calls = []
            def run(argv):
                calls.append(argv[0])
                if argv == action['apply']:
                    self.assertTrue(journal.exists(), 'recovery must be durable before mutation')
                    artifact.write_text('new')
                if argv == action['health']:
                    raise RuntimeError('injected canary failure')
                if argv == action['rollback']:
                    artifact.write_text('old')
                return {}
            result = DEFENSE.execute(action, 'fixture', journal, run)
            self.assertEqual(result['status'], 'recovered')
            self.assertEqual(artifact.read_text(), 'old')
            self.assertEqual(calls, ['/test/apply', '/test/health', '/test/rollback', '/test/recovery_check'])

    def test_recovery_failure_is_durable_and_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'journal.json'
            journal = {'action': 'fixture', 'rollback': ['/test/fail'], 'recovery_check': ['/test/check']}
            def fail(argv):
                raise RuntimeError('restore failed')
            self.assertEqual(DEFENSE.recover(journal, path, fail)['status'], 'recovery_failed')
            self.assertIn('recovery_failed', path.read_text())

    def test_success_installs_only_verified_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact, candidate = root / 'current', root / 'candidate'
            artifact.write_text('old')
            candidate.write_text('new')
            action = {**self.action(), 'artifact': str(artifact), 'candidate': str(candidate),
                      'current_sha256': DEFENSE.digest(str(artifact)), 'candidate_sha256': DEFENSE.digest(str(candidate))}
            def run(argv):
                if argv == action['apply']:
                    artifact.write_text('new')
                return {}
            self.assertEqual(DEFENSE.execute(action, 'fixture', root / 'journal.json', run)['status'], 'completed')
            candidate.write_text('tampered')
            with self.assertRaisesRegex(ValueError, 'changed before execution'):
                DEFENSE.execute(action, 'fixture', root / 'other.json', run)
