"""Failure injection for scan liveness and durable health notification episodes."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'scan_watchdog', ROOT / 'ansible/roles/update_monitor/files/homelab_scan_watchdog.py')
WATCHDOG = importlib.util.module_from_spec(spec)
spec.loader.exec_module(WATCHDOG)
NOW = datetime(2026, 9, 6, 12, tzinfo=UTC)


class ScanWatchdogTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / 'cve-state.json'
        self.status = self.state.with_suffix('.status.json')
        self.observation = self.state.with_suffix('.watchdog.json')
        self.service = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'Result': 'success'}
        self.timer = {'LoadState': 'loaded', 'ActiveState': 'active'}
        patcher = mock.patch.object(WATCHDOG, 'unit_state', side_effect=lambda unit: (
            self.timer if unit.endswith('.timer') else self.service))
        self.units = patcher.start()
        self.addCleanup(patcher.stop)
        sender = mock.patch.object(WATCHDOG, 'notify')
        self.send = sender.start()
        self.addCleanup(sender.stop)
        self.complete(NOW - timedelta(hours=1))

    def write_status(self, phase, when=NOW):
        self.status.write_text(json.dumps({'status': phase, 'observed_at': when.isoformat()}))

    def complete(self, when):
        self.state.write_text(json.dumps({'schema': 1, 'updated_at': when.isoformat(),
                                         'findings': {'prior': {'id': 'CVE-2099-1'}}, 'coverage': {}}))
        self.write_status('complete', when)
        self.service.update(ActiveState='inactive', Result='success')

    def check(self, when=NOW, **kwargs):
        return WATCHDOG.check(self.state, self.observation, when, **kwargs)

    def test_fresh_completion_is_silent_and_does_not_change_scan_evidence(self):
        before = (self.state.read_bytes(), self.status.read_bytes())
        self.assertEqual(self.check()['status'], 'healthy')
        self.assertEqual(before, (self.state.read_bytes(), self.status.read_bytes()))
        self.send.assert_not_called()
        self.assertEqual(self.observation.stat().st_mode & 0o777, 0o600)

    def test_missing_and_corrupt_status_are_unknown(self):
        for raw in (None, '[1]', '{', '{}', '{"status":"unexpected","observed_at":"2026-09-06T12:00:00Z"}'):
            with self.subTest(raw=raw):
                if raw is None:
                    self.status.unlink(missing_ok=True)
                else:
                    self.status.write_text(raw)
                self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')

    def test_missing_or_invalid_evidence_cannot_look_healthy(self):
        for raw in (None, '{}', '[1]', '{', '{"schema":2}'):
            with self.subTest(raw=raw):
                if raw is None:
                    self.state.unlink(missing_ok=True)
                else:
                    self.state.write_text(raw)
                self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')

    def test_failed_systemd_result_overrides_old_complete_status(self):
        for reason in ('timeout', 'oom-kill', 'signal', 'exit-code'):
            with self.subTest(reason=reason):
                self.service.update(ActiveState='failed', Result=reason)
                result = self.check(check_only=True)
                self.assertEqual(result['status'], 'unhealthy')

    def test_interrupted_running_status_is_detected_even_after_reset_failed(self):
        self.write_status('running', NOW - timedelta(minutes=10))
        self.assertEqual(self.check()['status'], 'unhealthy')
        self.send.assert_called_once()

    def test_new_scan_does_not_mask_overdue_completion(self):
        self.complete(NOW - timedelta(hours=37))
        self.write_status('running', NOW - timedelta(minutes=10))
        self.service['ActiveState'] = 'activating'
        self.assertEqual(self.check()['status'], 'unhealthy')
        self.send.assert_called_once()

    def test_first_scan_can_run_but_has_a_deadline(self):
        self.state.unlink()
        self.write_status('running')
        self.service['ActiveState'] = 'activating'
        self.assertEqual(self.check()['status'], 'running')
        self.send.assert_not_called()
        self.assertEqual(self.check(NOW + timedelta(hours=2, minutes=6))['status'], 'unhealthy')
        self.send.assert_called_once()

    def test_future_naive_and_mismatched_timestamps_are_invalid(self):
        for value in ('2026-09-07T12:00:00Z', '2026-09-06T12:00:00', None, 12):
            with self.subTest(value=value):
                self.status.write_text(json.dumps({'status': 'complete', 'observed_at': value}))
                self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')
        self.write_status('complete')  # Does not match evidence from an hour earlier.
        self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')

    def test_inactive_missing_or_unqueryable_units_are_unknown(self):
        for update in ({'ActiveState': 'inactive'}, {'LoadState': 'not-found'}):
            with self.subTest(update=update):
                self.timer.update(update)
                self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')
        self.units.side_effect = subprocess.TimeoutExpired('systemctl', 15)
        self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')

    def test_notification_is_once_per_episode_across_checks_and_scan_retries(self):
        self.write_status('failed')
        self.check()
        self.check(NOW + timedelta(minutes=5))
        self.write_status('running', NOW + timedelta(minutes=6))
        self.service['ActiveState'] = 'activating'
        self.check(NOW + timedelta(minutes=10))
        self.write_status('failed', NOW + timedelta(minutes=11))
        self.service.update(ActiveState='failed', Result='exit-code')
        self.check(NOW + timedelta(minutes=15))
        self.send.assert_called_once()

    def test_recovery_requires_new_completed_evidence_and_is_once_per_episode(self):
        self.write_status('failed')
        self.check()
        self.complete(NOW - timedelta(hours=1))  # Resetting status is not recovery.
        self.assertEqual(self.check()['status'], 'unhealthy')
        self.send.assert_called_once()
        self.complete(NOW + timedelta(minutes=1))
        self.assertEqual(self.check(NOW + timedelta(minutes=5))['status'], 'healthy')
        self.assertIsNone(json.loads(self.observation.read_text())['episode_started_at'])
        self.check(NOW + timedelta(minutes=10))
        self.assertEqual(self.send.call_count, 2)
        self.write_status('failed', NOW + timedelta(minutes=11))
        self.check(NOW + timedelta(minutes=15))
        self.assertEqual(self.send.call_count, 3)

    def test_failed_delivery_retains_unknown_state_and_retries_without_touching_findings(self):
        self.write_status('failed')
        before = self.state.read_bytes()
        self.send.side_effect = RuntimeError('bridge unavailable')
        with self.assertRaises(RuntimeError):
            self.check()
        stored = json.loads(self.observation.read_text())
        self.assertEqual(stored['status'], 'unhealthy')
        self.assertFalse(stored['notified'])
        attempted = self.send.call_args
        self.assertEqual(stored['pending_notification'], attempted.args[0])
        self.timer['ActiveState'] = 'inactive'  # A changed reason must not change retry identity.
        self.send.side_effect = None
        self.check(NOW + timedelta(minutes=5))
        self.assertEqual(self.send.call_args, attempted)
        self.assertTrue(json.loads(self.observation.read_text())['notified'])
        self.assertNotIn('pending_notification', json.loads(self.observation.read_text()))
        self.assertEqual(before, self.state.read_bytes())

    def test_failed_recovery_notification_is_retried(self):
        self.write_status('failed')
        self.check()
        self.complete(NOW + timedelta(minutes=1))
        self.send.side_effect = RuntimeError('bridge unavailable')
        with self.assertRaises(RuntimeError):
            self.check(NOW + timedelta(minutes=5))
        self.assertTrue(json.loads(self.observation.read_text())['notified'])
        self.send.side_effect = None
        self.check(NOW + timedelta(minutes=10))
        self.assertIsNone(json.loads(self.observation.read_text())['episode_started_at'])

    def test_read_only_check_never_writes_or_notifies_even_when_unhealthy(self):
        self.status.unlink()
        before = sorted(self.root.iterdir())
        self.assertEqual(self.check(check_only=True)['status'], 'unhealthy')
        self.assertEqual(before, sorted(self.root.iterdir()))
        self.send.assert_not_called()

    def test_scan_transition_during_observation_does_not_report_false_interruption(self):
        def unit_with_scan_start(unit):
            self.write_status('running')
            return self.timer if unit.endswith('.timer') else self.service
        self.units.side_effect = unit_with_scan_start
        self.assertEqual(self.check()['status'], 'running')
        self.send.assert_not_called()


if __name__ == '__main__':
    unittest.main()
