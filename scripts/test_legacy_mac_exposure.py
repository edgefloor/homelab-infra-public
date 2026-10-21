import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parent / "legacy" / "mac_exposure" / "expose.py"
SPEC = importlib.util.spec_from_file_location("expose", MODULE_PATH)
subject = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(subject)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return self.responses.pop(0)


class ExposureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.state_path = root / "state.json"
        self.caddyfile = root / "Caddyfile"
        self.config = subject.Config(
            org_id="org-1",
            domain_id="domain-1",
            site_id=7,
            role_ids=[4],
            idp_id=1,
            base_domain="homelab.example",
            proxy_address="10.42.0.51",
            proxy_port=8090,
            newt_address="10.42.0.210",
            ssh_host="root@198.51.100.24",
            caddy_binary="/opt/homebrew/bin/caddy",
            caddyfile=self.caddyfile,
            state_file=self.state_path,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_caddy_config_proxies_exact_hosts_to_mac_loopback(self):
        manager = subject.ExposureManager(self.config, FakeTransport([]), reload_caddy=lambda: None)
        manager.write_proxy_config(
            {
                "demo": {
                    "target": "http://127.0.0.1:3000",
                    "resource_id": 12,
                }
            }
        )
        rendered = self.caddyfile.read_text(encoding="utf-8")
        self.assertIn("http://:8090", rendered)
        self.assertIn("bind 10.42.0.51", rendered)
        self.assertIn("host demo.homelab.example", rendered)
        self.assertIn("remote_ip 10.42.0.210", rendered)
        self.assertIn("reverse_proxy 127.0.0.1:3000", rendered)
        self.assertIn('respond "No active exposure" 404', rendered)

    def test_create_registers_pangolin_auth_target_and_local_proxy(self):
        transport = FakeTransport(
            [
                {"resources": [], "pagination": {"total": 0}},
                {"resourceId": 12},
                {"resourceId": 12},
                {},
                {"targetId": 31},
            ]
        )
        reloads = []
        manager = subject.ExposureManager(
            self.config,
            transport,
            reload_caddy=lambda: reloads.append(True),
        )
        result = manager.expose("demo", "http://localhost:3000")

        self.assertEqual("https://demo.homelab.example", result["url"])
        self.assertEqual(1, len(reloads))
        self.assertEqual(
            ("PUT", "/org/org-1/public-resource", {
                "name": "On-demand demo",
                "subdomain": "demo",
                "domainId": "domain-1",
                "mode": "http",
            }),
            transport.calls[1],
        )
        self.assertEqual(
            ("POST", "/public-resource/12", {
                "niceId": "on-demand-demo",
                "sso": True,
                "skipToIdpId": 1,
                "setHostHeader": "demo.homelab.example",
            }),
            transport.calls[2],
        )
        self.assertEqual(
            ("POST", "/public-resource/12/roles", {"roleIds": [4]}),
            transport.calls[3],
        )
        self.assertEqual("10.42.0.51", transport.calls[4][2]["ip"])
        self.assertEqual(8090, transport.calls[4][2]["port"])
        self.assertEqual(7, transport.calls[4][2]["siteId"])
        self.assertEqual("http", transport.calls[4][2]["method"])

    def test_generated_name_is_readable_and_skips_known_collisions(self):
        with (
            mock.patch.object(
                subject.secrets,
                "choice",
                side_effect=["bright", "otter", "quiet", "falcon"],
            ),
            mock.patch.object(subject.secrets, "token_hex", side_effect=["a1b2", "c3d4"]),
        ):
            name = subject.generate_name({"bright-otter-a1b2"})

        self.assertEqual("quiet-falcon-c3d4", name)

    def test_generated_exposure_retries_a_remote_collision_without_adopting_it(self):
        transport = FakeTransport(
            [
                {"resources": [], "pagination": {"total": 0}},
                {
                    "resources": [{"fullDomain": "bright-otter-a1b2.homelab.example"}],
                    "pagination": {"total": 1},
                },
                {"resources": [], "pagination": {"total": 0}},
                {"resourceId": 12},
                {"resourceId": 12},
                {},
                {"targetId": 31},
            ]
        )
        manager = subject.ExposureManager(
            self.config,
            transport,
            reload_caddy=lambda: None,
        )
        with mock.patch.object(
            subject,
            "generate_name",
            side_effect=["bright-otter-a1b2", "quiet-falcon-c3d4"],
        ):
            result = manager.expose_generated("http://127.0.0.1:3000")

        self.assertEqual("quiet-falcon-c3d4", result["name"])
        creates = [call for call in transport.calls if call[0:2] == ("PUT", "/org/org-1/public-resource")]
        self.assertEqual(1, len(creates))
        self.assertEqual("quiet-falcon-c3d4", creates[0][2]["subdomain"])

    def test_generated_exposure_never_updates_an_existing_local_name(self):
        self.state_path.write_text(
            json.dumps({"schema_version": 1, "exposures": {
                "bright-otter-a1b2": {"target": "http://127.0.0.1:3000", "resource_id": 8}
            }}),
            encoding="utf-8",
        )
        transport = FakeTransport(
            [
                {"resources": [], "pagination": {"total": 0}},
                {"resources": [], "pagination": {"total": 0}},
                {"resourceId": 12},
                {"resourceId": 12},
                {},
                {"targetId": 31},
            ]
        )
        manager = subject.ExposureManager(
            self.config,
            transport,
            reload_caddy=lambda: None,
        )
        with mock.patch.object(
            subject,
            "generate_name",
            side_effect=["bright-otter-a1b2", "quiet-falcon-c3d4"],
        ):
            result = manager.expose_generated("http://127.0.0.1:4000")

        self.assertEqual("quiet-falcon-c3d4", result["name"])
        state = json.loads(self.state_path.read_text(encoding="utf-8"))["exposures"]
        self.assertEqual("http://127.0.0.1:3000", state["bright-otter-a1b2"]["target"])

    def test_update_only_reloads_the_mac_proxy(self):
        self.state_path.write_text(
            json.dumps({"schema_version": 1, "exposures": {
                "demo": {"target": "http://127.0.0.1:3000", "resource_id": 12}
            }}),
            encoding="utf-8",
        )
        transport = FakeTransport([])
        manager = subject.ExposureManager(
            self.config,
            transport,
            reload_caddy=lambda: None,
        )
        manager.expose("demo", "http://127.0.0.1:4000")
        self.assertEqual([], transport.calls)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual("http://127.0.0.1:4000", state["exposures"]["demo"]["target"])

    def test_remove_deletes_public_resource_then_local_route(self):
        self.state_path.write_text(
            json.dumps({"schema_version": 1, "exposures": {
                "demo": {"target": "http://127.0.0.1:3000", "resource_id": 12}
            }}),
            encoding="utf-8",
        )
        transport = FakeTransport([{}])
        manager = subject.ExposureManager(
            self.config,
            transport,
            reload_caddy=lambda: None,
        )
        manager.remove("demo")
        self.assertEqual([("DELETE", "/public-resource/12", None)], transport.calls)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual({}, state["exposures"])

    def test_rejects_nonlocal_targets(self):
        manager = subject.ExposureManager(self.config, FakeTransport([]), reload_caddy=lambda: None)
        for target in (
            "http://10.42.0.20:3000",
            "http://example.com:3000",
            "ftp://127.0.0.1:3000",
            "http://127.0.0.1:3000/path",
        ):
            with self.subTest(target=target), self.assertRaises(subject.ExposureError):
                manager.expose("demo", target)

    def test_api_key_file_must_be_private(self):
        key_file = Path(self.temporary.name) / "api-key"
        key_file.write_text("key-id.key-secret\n", encoding="utf-8")
        os.chmod(key_file, 0o644)
        with self.assertRaisesRegex(subject.ExposureError, "mode 0600"):
            subject.read_secret(key_file)
        os.chmod(key_file, 0o600)
        self.assertEqual("key-id.key-secret", subject.read_secret(key_file))


if __name__ == "__main__":
    unittest.main()
