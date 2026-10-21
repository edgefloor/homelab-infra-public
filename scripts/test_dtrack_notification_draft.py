import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class DependencyTrackNotificationDraftTests(unittest.TestCase):
    def test_trigger_guard_accepts_future_08_utc_and_rejects_local_time_drift(self):
        task = yaml.safe_load((ROOT / 'ansible/playbooks/tasks/dependency-track-verify-trigger.yml').read_text())[0]
        script = task['ansible.builtin.command']['argv'][2]
        tomorrow = datetime.now(timezone.utc).replace(hour=8, minute=0, second=0, microsecond=0) + timedelta(days=1)
        cases = [(tomorrow, True), (tomorrow.replace(hour=6), False),
                 (tomorrow.replace(hour=7), False), (tomorrow.replace(second=30), False),
                 (tomorrow - timedelta(days=3), False)]
        for trigger, accepted in cases:
            with self.subTest(trigger=trigger.isoformat()):
                result = subprocess.run([sys.executable, '-c', script, str(int(trigger.timestamp() * 1000))],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_workflow_uses_only_native_nodes_and_stays_inactive(self):
        flow = json.loads((ROOT / 'ansible/files/dependency-track-matrix-workflow.json').read_text())
        self.assertIs(flow['active'], False)
        self.assertEqual({node['type'] for node in flow['nodes']},
                         {'n8n-nodes-base.webhook', 'n8n-nodes-base.if', 'n8n-nodes-base.matrix'})
        webhook = next(node for node in flow['nodes'] if node['type'].endswith('.webhook'))
        self.assertEqual(webhook['parameters']['authentication'], 'headerAuth')
        self.assertEqual(webhook['parameters']['responseMode'], 'lastNode')
        matrix = next(node for node in flow['nodes'] if node['type'].endswith('.matrix'))
        self.assertEqual(matrix['parameters']['roomId'], '__MATRIX_ROOM_ID__')
        self.assertEqual(matrix['parameters']['messageFormat'], 'plain')
        self.assertNotIn('accessToken', json.dumps(flow))

    def test_native_alert_owns_daily_summary_and_remains_disabled(self):
        alert = json.loads((ROOT / 'ansible/files/dependency-track-notification-rule.json').read_text())
        self.assertFalse(alert['enabled'])
        self.assertEqual(alert['notifyOn'], ['NEW_VULNERABILITIES_SUMMARY'])
        self.assertTrue(alert['scheduleSkipUnchanged'])
        self.assertTrue(alert['notifyChildren'])
        self.assertEqual(alert['scheduleCron'], '0 8 * * *')
        self.assertIn('CRITICAL', alert['filterExpression'])
        self.assertIn('HIGH', alert['filterExpression'])
        # The v5.2 runtime column is narrower than its advertised API limit.
        self.assertLessEqual(len(alert['filterExpression']), 255)
        self.assertNotIn('notificationLevel', alert)

    def test_native_expressions_filter_and_format_v5_summaries(self):
        flow = json.loads((ROOT / 'ansible/files/dependency-track-matrix-workflow.json').read_text())
        predicate = flow['nodes'][1]['parameters']['conditions']['conditions'][0]['leftValue']
        message = flow['nodes'][2]['parameters']['text']
        script = r'''
const assert = require('node:assert/strict');
const [predicate, message] = JSON.parse(process.argv[1]).map(s =>
  new Function('$json', 'return (' + s.slice(3, -2) + ')'));
const fixture = {body:{notification:{group:'GROUP_NEW_VULNERABILITIES_SUMMARY',subject:{
  overview:{newVulnerabilitiesCountBySeverity:{HIGH:2}},
  projectSummaries:[{project:{name:'service'},newVulnerabilitiesCountBySeverity:{HIGH:2}},
    {project:{name:'medium-only'},newVulnerabilitiesCountBySeverity:{MEDIUM:4}}]
}}}};
assert.equal(predicate(fixture), true);
assert.match(message(fixture), /0 critical, 2 high/);
assert.match(message(fixture), /service: 0 critical, 2 high/);
assert.ok(message(fixture).includes('\nNew unsuppressed findings:'));
assert.ok(!message(fixture).includes('\\n'));
assert.doesNotMatch(message(fixture), /medium-only/);
fixture.body.notification.subject.overview.newVulnerabilitiesCountBySeverity = {CRITICAL:1};
assert.equal(predicate(fixture), true);
assert.match(message(fixture), /1 critical, 0 high/);
fixture.body.notification.subject.overview.newVulnerabilitiesCountBySeverity = {MEDIUM:4};
assert.equal(predicate(fixture), false);
fixture.body.notification.subject.overview.newVulnerabilitiesCountBySeverity = {};
assert.equal(predicate(fixture), false);
fixture.body.notification.group = 'GROUP_BOM_PROCESSED';
assert.equal(predicate(fixture), false);
'''
        result = subprocess.run(['node', '-e', script, json.dumps([predicate, message])],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
