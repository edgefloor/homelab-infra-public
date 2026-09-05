#!/usr/bin/env python3

import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest import mock


BRIDGE_PATH = (
    pathlib.Path(__file__).parents[1]
    / "ansible/roles/tuwunel/files/crowdsec_matrix_bridge.py"
)
sys.path.insert(0, str(BRIDGE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("crowdsec_matrix_bridge", BRIDGE_PATH)
BRIDGE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BRIDGE)


class CrowdSecMatrixBridgeTests(unittest.TestCase):
    def test_formats_a_concise_alert_batch(self):
        message = BRIDGE.format_message(
            {
                "edge": "home-caddy",
                "alerts": [
                    {
                        "scenario": "crowdsecurity/http-sensitive-files",
                        "source": {"scope": "Ip", "value": "203.0.113.9"},
                        "events_count": 4,
                        "decisions": [{"type": "ban", "duration": "4h"}],
                    }
                ],
            }
        )
        self.assertEqual(
            message,
            "CrowdSec · Home Caddy\n"
            "1 new alert\n\n"
            "203.0.113.9\n"
            "Rule: http-sensitive-files\n"
            "Action: Ban · 4h\n"
            "Events: 4",
        )

    @mock.patch.object(BRIDGE, "country_name", return_value="United States")
    @mock.patch.object(BRIDGE.COUNTRY_DATABASE, "lookup", return_value="US")
    def test_adds_country_flag_and_name_above_crowdsec_source_ip(self, _lookup, _name):
        message = BRIDGE.format_message(
            {
                "edge": "pangolin-vps",
                "alerts": [
                    {
                        "scenario": "crowdsecurity/http-probing",
                        "source": {"scope": "Ip", "value": "198.51.100.20"},
                        "decisions": [{"type": "ban", "duration": "24h"}],
                    }
                ],
            }
        )
        self.assertIn(
            "🇺🇸 United States\n198.51.100.20\nRule: http-probing\nAction: Ban · 24h",
            message,
        )

    def test_displays_ban_hours_without_rounding_other_durations(self):
        for duration, expected in (
            ("4h0m0s", "4h"),
            ("8h", "8h"),
            ("12h0m0s", "12h"),
            ("3h59m30s", "3h59m30s"),
        ):
            with self.subTest(duration=duration):
                message = BRIDGE.format_message({
                    "edge": "home-caddy",
                    "alerts": [{"decisions": [{"type": "ban", "duration": duration}]}],
                })
                self.assertIn(f"Action: Ban · {expected}", message)
                self.assertNotIn("tier", message)

    def post_alerts(self, alerts, client):
        raw_body = json.dumps({"edge": "home-caddy", "alerts": alerts}).encode()
        handler = object.__new__(BRIDGE.BridgeHandler)
        handler.path = "/crowdsec"
        handler.headers = {
            "Authorization": "Bearer test-secret",
            "Content-Length": str(len(raw_body)),
        }
        handler.rfile = io.BytesIO(raw_body)
        handler.server = mock.Mock(
            webhook_secret="test-secret", matrix_clients={"security": client}
        )
        handler._json_response = mock.Mock()
        handler.do_POST()
        return handler._json_response.call_args.args[0]

    def test_sends_every_alert_separately_including_batches_larger_than_ten(self):
        client = mock.Mock()
        alerts = [
            {"scenario": f"rule-{i}", "source": {"value": f"192.168.1.{i}"}}
            for i in range(1, 13)
        ]
        self.assertEqual(self.post_alerts(alerts, client), 202)
        self.assertEqual(client.send.call_count, 12)
        ids = []
        for alert, call in zip(alerts, client.send.call_args_list):
            message, txn, context = call.args
            self.assertIn("1 new alert", message)
            self.assertEqual(message.count("Rule:"), 1)
            self.assertIn("Rule: " + alert["scenario"] + "\n", message)
            ids.append(txn)
        self.assertEqual(len(set(ids)), 12)

    def test_partial_delivery_retry_reuses_transaction_ids(self):
        client = mock.Mock()
        alerts = [{"scenario": "first"}, {"scenario": "second"}]
        client.send.side_effect = ["$first", RuntimeError("temporary failure")]
        self.assertEqual(self.post_alerts(alerts, client), 502)
        first_attempt = [call.args[1] for call in client.send.call_args_list]
        client.reset_mock(side_effect=True)
        self.assertEqual(self.post_alerts(alerts, client), 202)
        self.assertEqual(
            [call.args[1] for call in client.send.call_args_list], first_attempt
        )

    def test_rejects_invalid_batch_before_sending_any_alert(self):
        client = mock.Mock()
        self.assertEqual(self.post_alerts([{"scenario": "valid"}, None], client), 400)
        client.send.assert_not_called()

    @mock.patch.object(BRIDGE.COUNTRY_DATABASE, "lookup", return_value=None)
    def test_keeps_source_ip_when_country_is_unknown(self, _lookup):
        self.assertEqual(BRIDGE.format_source_ip("10.42.0.10"), "10.42.0.10")

    def test_transaction_id_is_deterministic_per_payload(self):
        first = BRIDGE.transaction_id(b'{"alerts":[1]}')
        second = BRIDGE.transaction_id(b'{"alerts":[1]}')
        different = BRIDGE.transaction_id(b'{"alerts":[2]}')
        self.assertEqual(first, second)
        self.assertNotEqual(first, different)

    @mock.patch.object(BRIDGE.request, "urlopen")
    def test_matrix_request_is_authenticated_idempotent_put(self, urlopen):
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
        urlopen.return_value = response

        client = BRIDGE.MatrixClient(
            "http://127.0.0.1:6167",
            "!room:matrix.homelab.example",
            "secret-token",
        )
        self.assertEqual(client.send("hello", "crowdsec_test"), "$event")

        sent_request = urlopen.call_args.args[0]
        self.assertEqual(sent_request.method, "PUT")
        self.assertIn("%21room%3Amatrix.homelab.example", sent_request.full_url)
        self.assertTrue(sent_request.full_url.endswith("/crowdsec_test"))
        self.assertEqual(sent_request.get_header("Authorization"), "Bearer secret-token")
        self.assertEqual(
            json.loads(sent_request.data),
            {"msgtype": "m.text", "body": "hello"},
        )

    @mock.patch.object(BRIDGE.request, "urlopen")
    def test_matrix_request_carries_bounded_machine_context(self, urlopen):
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(b'{"event_id":"$event"}')
        urlopen.return_value = response
        client = BRIDGE.MatrixClient(
            "http://127.0.0.1:6167",
            "!room:matrix.homelab.example",
            "secret-token",
        )
        context = {"schema": 1, "kind": "cve", "context": {"schema": 1}}

        client.send("alert", "cve_test", context)

        sent = json.loads(urlopen.call_args.args[0].data)
        self.assertEqual(sent[BRIDGE.MACHINE_CONTEXT_KEY], context)

    def test_rejects_empty_alert_batches(self):
        with self.assertRaisesRegex(ValueError, "non-empty alerts list"):
            BRIDGE.format_message({"edge": "pangolin-vps", "alerts": []})

    def test_formats_a_generic_cve_notification(self):
        self.assertEqual(
            BRIDGE.format_generic_notification(
                {
                    "kind": "cve",
                    "source": "Pocket ID",
                    "message": "1 new fixable critical vulnerability",
                }
            ),
            "CVE | Pocket ID\n1 new fixable critical vulnerability",
        )

    def test_validates_cve_machine_context(self):
        envelope = BRIDGE.machine_context(
            {
                "kind": "cve",
                "source": "Pangolin VPS",
                "context": {"schema": 1, "groups": []},
            }
        )
        self.assertEqual(envelope["kind"], "cve")
        self.assertEqual(envelope["context"]["groups"], [])

        with self.assertRaisesRegex(ValueError, "supported schema"):
            BRIDGE.machine_context(
                {"kind": "cve", "source": "Pangolin VPS", "context": {}}
            )

    def test_cve_context_converts_floats_for_matrix_canonical_json(self):
        envelope = BRIDGE.machine_context(
            {
                "kind": "cve",
                "source": "Pangolin VPS",
                "context": {
                    "schema": 1,
                    "groups": [{"cvss": {"score": 9.8, "nested": [7.5]}}],
                },
            }
        )

        self.assertEqual(
            envelope["context"]["groups"][0]["cvss"],
            {"score": "9.8", "nested": ["7.5"]},
        )

    def test_rejects_unknown_generic_notification_kind(self):
        with self.assertRaisesRegex(ValueError, "unsupported notification kind"):
            BRIDGE.format_generic_notification(
                {"kind": "chat", "source": "test", "message": "hello"}
            )

    def test_routes_every_supported_notification_kind(self):
        self.assertEqual(BRIDGE.notification_room("beszel"), "health")
        self.assertEqual(BRIDGE.notification_room("system"), "health")
        self.assertEqual(BRIDGE.notification_room("crowdsec"), "security")
        self.assertEqual(BRIDGE.notification_room("release"), "releases")
        self.assertEqual(BRIDGE.notification_room("cve"), "vulnerabilities")
    def test_rejects_unknown_notification_route(self):
        with self.assertRaisesRegex(ValueError, "unsupported notification kind"):
            BRIDGE.notification_room("chat")

    def test_formats_concise_beszel_status_notifications(self):
        self.assertEqual(
            BRIDGE.format_generic_notification(
                {
                    "kind": "beszel",
                    "title": "Connection to Caddy is down 🔴",
                    "message": (
                        "Connection to Caddy is down \n\n"
                        "https://beszel.homelab.example/system/caddy"
                    ),
                }
            ),
            "🔴 Caddy down",
        )
        self.assertEqual(
            BRIDGE.format_generic_notification(
                {
                    "kind": "beszel",
                    "title": "Connection to Caddy is up ✅",
                    "message": "Connection to Caddy is up",
                }
            ),
            "🟢 Caddy recovered",
        )

    def test_formats_concise_beszel_metric_notifications(self):
        self.assertEqual(
            BRIDGE.format_generic_notification(
                {
                    "kind": "beszel",
                    "title": "Jellyfin memory above threshold",
                    "message": (
                        "Memory averaged 92.50% for the previous 10 minutes.\n\n"
                        "https://beszel.homelab.example/system/jellyfin"
                    ),
                }
            ),
            "⚠️ Jellyfin: memory high\nMemory: 92.5% avg / 10m",
        )

    def test_formats_unknown_beszel_notifications_without_info_emoji(self):
        self.assertEqual(
            BRIDGE.format_generic_notification(
                {
                    "kind": "beszel",
                    "title": "Test Alert",
                    "message": "This is a notification from Beszel.",
                }
            ),
            "Beszel: Test Alert\nThis is a notification from Beszel.",
        )


if __name__ == "__main__":
    unittest.main()
