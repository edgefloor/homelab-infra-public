from pathlib import Path
import importlib.util
import unittest

PATH = Path(__file__).resolve().parents[1] / 'ansible/roles/beszel_hub/files/configure_monitoring.py'
SPEC = importlib.util.spec_from_file_location('beszel_monitoring', PATH)
monitoring = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitoring)


class NativeMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.systems = [{'id': 'system1', 'name': 'Host', 'users': ['owner'], 'status': 'up'}]
        self.existing = [{'id': 'status1', 'system': 'system1', 'user': 'owner',
                          'name': 'Status', 'value': 0, 'min': 7, 'triggered': True}]

    def test_preserves_existing_status_and_adds_native_failure_and_disk_alerts(self):
        changes = monitoring.alert_changes(self.systems, self.existing, ['Host'])
        additions = {data['name']: data for record_id, data in changes if record_id is None}
        self.assertEqual(set(additions), {'SystemdFailed', 'Disk'})
        self.assertEqual((additions['SystemdFailed']['value'], additions['SystemdFailed']['min']), (0, 0))
        self.assertEqual(additions['Disk']['value'], 85)
        self.assertEqual(self.existing[0]['min'], 7)
        self.assertTrue(self.existing[0]['triggered'])

    def test_second_reconciliation_is_empty(self):
        changes = monitoring.alert_changes(self.systems, self.existing, ['Host'])
        self.existing.extend({'id': str(i), **data} for i, (_, data) in enumerate(changes))
        self.assertEqual(monitoring.alert_changes(self.systems, self.existing, ['Host']), [])

    def test_missing_or_disconnected_system_prevents_alert_activation(self):
        with self.assertRaisesRegex(RuntimeError, 'missing'):
            monitoring.alert_changes(self.systems, self.existing, ['Other'])
        self.systems[0]['status'] = 'pending'
        with self.assertRaisesRegex(RuntimeError, 'connect'):
            monitoring.alert_changes(self.systems, self.existing, ['Host'])

    def test_duplicate_names_and_alerts_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'duplicate Beszel system names'):
            monitoring.alert_changes(self.systems * 2, self.existing, ['Host'])
        with self.assertRaisesRegex(RuntimeError, 'Duplicate native alerts'):
            monitoring.alert_changes(self.systems, self.existing * 2, ['Host'])


if __name__ == '__main__':
    unittest.main()
