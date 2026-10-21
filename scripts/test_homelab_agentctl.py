import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / 'ansible/roles/homelab_agent_service/files/homelab_agentctl.py'
SPEC = importlib.util.spec_from_file_location('homelab_agentctl', SOURCE)
AGENTCTL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(AGENTCTL)


class AgentCtlAlertTests(unittest.TestCase):
    @mock.patch.object(AGENTCTL, 'invoke', return_value=0)
    @mock.patch.object(AGENTCTL, 'targets')
    def test_alert_list_uses_the_single_alert_store_target(self, targets, invoke):
        target = {'host': '192.0.2.1', 'services': {'matrix-alerts': 'bridge.service'}}
        targets.return_value = {
            'pangolin': target,
            'caddy': {'host': '192.0.2.2', 'services': {'caddy': 'caddy.service'}},
        }
        argv = [
            'homelab-agentctl', 'alerts', 'list', '--kind', 'cve',
            '--contains', 'CVE-2026-1234', '--limit', '5',
        ]
        with mock.patch.object(sys, 'argv', argv):
            self.assertEqual(AGENTCTL.main(), 0)

        request = json.loads(invoke.call_args.args[3])
        self.assertEqual(invoke.call_args.args[:3], (target, ['alerts'], 30))
        self.assertEqual(request, {
            'action': 'list', 'kind': 'cve', 'contains': 'CVE-2026-1234', 'limit': 5,
        })

    @mock.patch.object(AGENTCTL, 'evidence_request', return_value=0)
    @mock.patch.object(AGENTCTL, 'targets')
    def test_snapshot_artifact_sends_exact_binding_references(
        self, targets, evidence_request
    ):
        evidence_target = {
            'host': '192.0.2.2',
            'display_name': 'Caddy',
            'services': {'caddy': 'caddy.service'},
        }
        targets.return_value = {'caddy': evidence_target}
        arguments = {
            'snapshot_sha256': 'a' * 64,
            'finding_sha256': 'b' * 64,
            'container': 'caddy',
            'path': '/usr/bin/caddy',
        }
        argv = [
            'homelab-agentctl', 'snapshot-artifact', 'caddy',
            'extract_file', json.dumps(arguments),
        ]

        with mock.patch.object(sys, 'argv', argv):
            self.assertEqual(AGENTCTL.main(), 0)

        evidence_request.assert_called_once_with(
            evidence_target,
            {
                'action': 'snapshot_artifact',
                'operation': 'extract_file',
                'arguments': arguments,
            },
            360,
        )

    @mock.patch.object(AGENTCTL, 'evidence_request')
    @mock.patch.object(AGENTCTL, 'targets')
    def test_legacy_artifact_command_is_not_public(
        self, targets, evidence_request
    ):
        targets.return_value = {
            'alerts': {'host': '192.0.2.1',
                       'services': {'matrix-alerts': 'bridge.service'}},
            'caddy': {'host': '192.0.2.2', 'display_name': 'Caddy',
                      'services': {}},
        }
        argv = [
            'homelab-agentctl', 'artifact', 'caddy',
            'crowdsec_' + 'a' * 40, 'inspect_executable', '{}',
        ]

        with mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(sys, 'stderr'), \
                self.assertRaises(SystemExit) as raised:
            AGENTCTL.main()

        self.assertEqual(2, raised.exception.code)
        targets.assert_not_called()
        evidence_request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
