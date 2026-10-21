#!/usr/bin/env python3

import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

BRIDGE_PATH = pathlib.Path(__file__).parents[1] / 'ansible/roles/tuwunel/files/crowdsec_matrix_bridge.py'
sys.path.insert(0, str(BRIDGE_PATH.parent))
SPEC = importlib.util.spec_from_file_location('crowdsec_matrix_bridge', BRIDGE_PATH)
BRIDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BRIDGE)


class CrowdSecMatrixBridgeTests(unittest.TestCase):
    def post_payload(self, payload, clients, alert_store=None):
        raw_body = json.dumps(payload).encode()
        handler = object.__new__(BRIDGE.BridgeHandler)
        handler.path = '/crowdsec'
        handler.headers = {'Authorization': 'Bearer test-secret', 'Content-Length': str(len(raw_body))}
        handler.rfile = io.BytesIO(raw_body)
        handler.server = mock.Mock(
            webhook_secret='test-secret', matrix_clients=clients, alert_store=alert_store,
        )
        handler._json_response = mock.Mock()
        handler.do_POST()
        return handler._json_response.call_args.args[0]

    def post_alerts(self, alerts, client):
        return self.post_payload({'edge': 'home-caddy', 'alerts': alerts}, {'security': client})

    def test_crowdsec_alert_preserves_decision_duration_and_source(self):
        alert = {'scenario': 'crowdsecurity/http-sensitive-files',
                 'source': {'scope': 'Ip', 'value': '203.0.113.9'}, 'events_count': 4,
                 'decisions': [{'type': 'ban', 'duration': '4h'}]}
        with mock.patch.object(BRIDGE.COUNTRY_DATABASE, 'lookup', return_value=None):
            message = BRIDGE.format_message({'edge': 'home-caddy', 'alerts': [alert]})
        self.assertEqual(message, 'CrowdSec · Home Caddy\n1 new alert\n\n203.0.113.9\n'
                                 'Rule: http-sensitive-files\nAction: Ban · 4h\nEvents: 4')
        with mock.patch.object(BRIDGE.COUNTRY_DATABASE, 'lookup', return_value='US'), \
                mock.patch.object(BRIDGE, 'country_name', return_value='United States'):
            message = BRIDGE.format_message({'edge': 'home-caddy', 'alerts': [alert]})
        self.assertIn('🇺🇸 United States\n203.0.113.9', message)

    def test_displays_ban_hours_without_rounding_other_durations(self):
        for duration, expected in [('4h0m0s', '4h'), ('8h', '8h'), ('12h0m0s', '12h'), ('3h59m30s', '3h59m30s')]:
            with self.subTest(duration=duration):
                message = BRIDGE.format_message({'edge': 'home-caddy', 'alerts': [
                    {'decisions': [{'type': 'ban', 'duration': duration}]}]})
                self.assertIn(f'Action: Ban · {expected}', message)

    def test_sends_every_alert_separately_including_batches_larger_than_ten(self):
        client = mock.Mock()
        alerts = [{'scenario': f'rule-{i}', 'source': {'value': f'192.168.1.{i}'}} for i in range(1, 13)]
        self.assertEqual(self.post_alerts(alerts, client), 202)
        self.assertEqual(client.send.call_count, len(alerts))
        for alert, call in zip(alerts, client.send.call_args_list):
            self.assertEqual(call.args[0].count('Rule:'), 1)
            self.assertIn('Rule: ' + alert['scenario'] + '\n', call.args[0])
        self.assertEqual(len({call.args[1] for call in client.send.call_args_list}), len(alerts))

    def test_partial_delivery_retry_reuses_transaction_ids(self):
        client = mock.Mock()
        alerts = [{'scenario': 'first'}, {'scenario': 'second'}]
        client.send.side_effect = ['$first', RuntimeError('temporary failure')]
        self.assertEqual(self.post_alerts(alerts, client), 502)
        first_attempt = [call.args[1] for call in client.send.call_args_list]
        client.reset_mock(side_effect=True)
        self.assertEqual(self.post_alerts(alerts, client), 202)
        self.assertEqual([call.args[1] for call in client.send.call_args_list], first_attempt)

    def test_rejects_invalid_batch_before_sending_any_alert(self):
        for alerts in ([], [{'scenario': 'valid'}, None]):
            with self.subTest(alerts=alerts):
                client = mock.Mock()
                self.assertEqual(self.post_alerts(alerts, client), 400)
                client.send.assert_not_called()

    @mock.patch.object(BRIDGE.request, 'urlopen')
    def test_matrix_request_preserves_body_context_and_authenticated_transaction(self, urlopen):
        urlopen.return_value.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
        client = BRIDGE.MatrixClient('http://127.0.0.1:6167', '!room:example.test', 'secret-token')
        context = {'schema': 1, 'kind': 'cve', 'context': {'schema': 1}}
        for machine_context in (None, context):
            with self.subTest(context=machine_context):
                urlopen.return_value.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
                self.assertEqual(client.send('hello', 'transaction-1', machine_context), '$event')
                sent = urlopen.call_args.args[0]
                self.assertEqual(sent.method, 'PUT')
                self.assertIn('%21room%3Aexample.test', sent.full_url)
                self.assertTrue(sent.full_url.endswith('/transaction-1'))
                self.assertEqual(sent.get_header('Authorization'), 'Bearer secret-token')
                expected = {'msgtype': 'm.text', 'body': 'hello'}
                if machine_context is not None:
                    expected[BRIDGE.MACHINE_CONTEXT_KEY] = machine_context
                self.assertEqual(json.loads(sent.data), expected)

    def test_persists_complete_payload_and_matrix_delivery_receipt(self):
        payload = {
            'kind': 'cve',
            'source': 'Caddy',
            'message': 'new finding',
            'observed_at': '2026-09-07T17:30:00+00:00',
            'context': {
                'schema': 2,
                'groups': [{'id': 'CVE-2026-1234', 'occurrences': [{'artifact': 'caddy:2.11.4'}]}],
            },
        }
        raw = json.dumps(payload).encode()
        record_id = BRIDGE.transaction_id(raw)
        client = mock.Mock()
        client.send.return_value = '$matrix-event'
        with tempfile.TemporaryDirectory() as directory:
            store = BRIDGE.AlertStore(pathlib.Path(directory))
            self.assertEqual(
                self.post_payload(payload, {'vulnerabilities': client}, alert_store=store),
                202,
            )
            record = store.get(record_id)

        self.assertEqual(record['record_id'], record_id)
        self.assertEqual(record['kind'], 'cve')
        self.assertEqual(record['payload'], payload)
        self.assertEqual(record['status'], 'delivered')
        self.assertEqual(record['deliveries'], [
            {
                'room': 'vulnerabilities',
                'transaction_id': record_id,
                'matrix_event_id': '$matrix-event',
            },
        ])

    def test_cve_webhook_is_notify_only_even_when_payload_mentions_zag(self):
        payload = {
            'kind': 'cve',
            'source': 'Pangolin VPS',
            'message': '@zag:matrix.homelab.example investigate HIGH CVE-2026-1234',
            'observed_at': '2026-09-07T17:30:00+00:00',
            'context': {
                'schema': 2,
                'groups': [{
                    'id': 'CVE-2026-1234',
                    'occurrences': [{
                        'artifact': 'example/image:1.0',
                        'containers': [{'name': 'example-service'}],
                    }],
                }],
            },
        }
        record_id = BRIDGE.transaction_id(json.dumps(payload).encode())
        client = mock.Mock()
        client.send.return_value = '$matrix-event'

        with mock.patch.dict(
            BRIDGE.os.environ,
            {'CVE_INVESTIGATOR_USER_ID': '@zag:matrix.homelab.example'},
        ):
            self.assertEqual(
                self.post_payload(payload, {'vulnerabilities': client}),
                202,
            )

        self.assertEqual(client.send.call_count, 1)
        message, transaction, context = client.send.call_args_list[0].args
        self.assertEqual(transaction, record_id)
        self.assertNotIn('@zag:matrix.homelab.example', message)
        self.assertIn('Target: Pangolin VPS', message)
        self.assertIn('Service: example-service', message)
        self.assertIn('Observed: 2026-09-07T17:30:00+00:00', message)
        self.assertIn('Advisory: CVE-2026-1234', message)
        self.assertIn(f'Alert record: {record_id}', message)
        self.assertEqual(context['record_id'], record_id)
        self.assertEqual(context['observed_at'], payload['observed_at'])
        self.assertEqual(context['notification_mode'], 'notify_only')
        self.assertEqual(
            client.send.call_args_list[0].kwargs,
            {},
        )

    @mock.patch.object(BRIDGE.request, 'urlopen')
    def test_matrix_request_carries_structured_user_mentions(self, urlopen):
        urlopen.return_value.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
        client = BRIDGE.MatrixClient(
            'http://127.0.0.1:6167', '!room:example.test', 'secret-token'
        )

        client.send(
            'CVE alert',
            'transaction-1',
            mentions=['@zag:matrix.homelab.example'],
        )

        sent = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(
            sent['m.mentions'],
            {'user_ids': ['@zag:matrix.homelab.example']},
        )

    @mock.patch.object(BRIDGE.request, 'urlopen')
    def test_matrix_request_carries_thread_relation(self, urlopen):
        urlopen.return_value.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
        client = BRIDGE.MatrixClient(
            'http://127.0.0.1:6167', '!room:example.test', 'secret-token'
        )

        client.send('triage', 'transaction-2', thread_root='$root')

        sent = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(
            sent['m.relates_to'],
            {
                'rel_type': 'm.thread',
                'event_id': '$root',
                'is_falling_back': True,
                'm.in_reply_to': {'event_id': '$root'},
            },
        )

    @mock.patch.object(BRIDGE.request, 'urlopen')
    def test_matrix_thread_can_reply_to_the_request_event(self, urlopen):
        urlopen.return_value.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
        client = BRIDGE.MatrixClient(
            'http://127.0.0.1:6167', '!room:example.test', 'secret-token'
        )

        client.send('answer', 'transaction-3', thread_root='$root', reply_to='$request')

        sent = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(sent['m.relates_to']['event_id'], '$root')
        self.assertEqual(sent['m.relates_to']['m.in_reply_to']['event_id'], '$request')

    def test_webhook_routes_to_only_the_intended_room_and_preserves_cve_context(self):
        routes = {'beszel': 'health', 'system': 'health', 'crowdsec': 'security',
                  'release': 'releases', 'cve': 'vulnerabilities', 'chat': None}
        for kind, room in routes.items():
            with self.subTest(kind=kind):
                clients = {name: mock.Mock() for name in set(routes.values()) if name}
                payload = {'kind': kind, 'source': 'test', 'title': 'Test', 'message': 'hello'}
                if kind == 'crowdsec':
                    payload['alerts'] = [{'scenario': 'rule'}]
                if kind == 'cve':
                    payload['context'] = {'schema': 1, 'groups': [{'cvss': {'score': 9.8, 'nested': [7.5]}}]}
                status = self.post_payload(payload, clients)
                self.assertEqual(status, 202 if room else 400)
                for name, client in clients.items():
                    expected_calls = int(name == room)
                    self.assertEqual(client.send.call_count, expected_calls)
                if kind == 'cve':
                    context = clients[room].send.call_args.args[2]
                    self.assertEqual(context['context']['groups'][0]['cvss'], {'score': '9.8', 'nested': ['7.5']})
                    for client in clients.values():
                        client.reset_mock()
                    payload['context'] = {}
                    self.assertEqual(self.post_payload(payload, clients), 400)
                    for client in clients.values():
                        client.send.assert_not_called()

    def test_generic_alert_examples_preserve_operator_information(self):
        examples = [
            ({'kind': 'cve', 'source': 'Pocket ID', 'message': '1 new fixable critical vulnerability'},
             'CVE | Pocket ID\n1 new fixable critical vulnerability'),
            ({'kind': 'beszel', 'title': 'Connection to Caddy is down 🔴',
              'message': 'Connection to Caddy is down \n\nhttps://example.test/system/caddy'}, '🔴 Caddy down'),
            ({'kind': 'beszel', 'title': 'Connection to Caddy is up ✅',
              'message': 'Connection to Caddy is up'}, '🟢 Caddy recovered'),
            ({'kind': 'beszel', 'title': 'Jellyfin memory above threshold',
              'message': 'Memory averaged 92.50% for the previous 10 minutes.\n\nhttps://example.test/system/jellyfin'},
             '⚠️ Jellyfin: memory high\nMemory: 92.5% avg / 10m'),
            ({'kind': 'beszel', 'title': 'Test Alert', 'message': 'This is a notification from Beszel.'},
             'Beszel: Test Alert\nThis is a notification from Beszel.'),
        ]
        for payload, expected in examples:
            with self.subTest(expected=expected):
                self.assertEqual(BRIDGE.format_generic_notification(payload), expected)


if __name__ == '__main__':
    unittest.main()
