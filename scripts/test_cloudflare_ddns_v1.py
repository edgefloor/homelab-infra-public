import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("cloudflare_ddns_v1.py")
SPEC = importlib.util.spec_from_file_location("cloudflare_ddns_v1", MODULE_PATH)
ddns = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = ddns
SPEC.loader.exec_module(ddns)


class MockTransport:
    def __init__(self, zone=None, record=None):
        self.zone = zone or {"id": "zone-1", "name": "homelab.example"}
        self.record = record or {
            "id": "record-1", "zone_id": "zone-1", "name": "home.homelab.example",
            "type": "A", "content": "192.0.2.1", "ttl": 300, "proxied": False,
        }
        self.calls = []

    def request(self, method, path, token, body=None):
        self.calls.append((method, path, body))
        if method == "PUT":
            return {"success": True, "result": body}
        return {"success": True, "result": self.zone if path.count("/") == 2 else self.record}

    @property
    def mutations(self):
        return [call for call in self.calls if call[0] != "GET"]


class DDNSTest(unittest.TestCase):
    def setUp(self):
        self.config = ddns.Config("zone-1", "record-1", "home.homelab.example", Path("/run/secrets/ddns-token"))

    def assert_refused_without_write(self, transport):
        with self.assertRaises(ddns.DDNSError):
            ddns.update(self.config, "192.0.2.2", transport, "secret-that-must-not-be-logged")
        self.assertEqual([], transport.mutations)

    def test_wrong_zone_id_causes_zero_mutating_requests(self):
        self.assert_refused_without_write(MockTransport(zone={"id": "wrong", "name": "homelab.example"}))

    def test_wrong_record_id_causes_zero_mutating_requests(self):
        record = dict(MockTransport().record, id="wrong")
        self.assert_refused_without_write(MockTransport(record=record))

    def test_wrong_record_name_causes_zero_mutating_requests(self):
        record = dict(MockTransport().record, name="other.homelab.example")
        self.assert_refused_without_write(MockTransport(record=record))

    def test_write_preserves_live_type_ttl_and_proxied(self):
        transport = MockTransport()
        self.assertTrue(ddns.update(self.config, "192.0.2.2", transport, "token"))
        self.assertEqual(["GET", "GET", "PUT"], [call[0] for call in transport.calls])
        body = transport.mutations[0][2]
        self.assertEqual({"type": "A", "name": "home.homelab.example", "content": "192.0.2.2", "ttl": 300, "proxied": False}, body)

    def test_each_write_rechecks_live_zone_and_record(self):
        transport = MockTransport()
        ddns.update(self.config, "192.0.2.2", transport, "token")
        ddns.update(self.config, "192.0.2.3", transport, "token")
        self.assertEqual(["GET", "GET", "PUT", "GET", "GET", "PUT"], [call[0] for call in transport.calls])


if __name__ == "__main__":
    unittest.main()
