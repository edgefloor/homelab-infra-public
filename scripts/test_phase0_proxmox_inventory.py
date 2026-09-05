import contextlib
import hashlib
import io
import json
import os
import socket
import ssl
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import phase0_proxmox_inventory as subject


TEST_HOST = "pve.internal.invalid"
TEST_ADDRESS = "10.23.45.67"


def approved_origin(addresses=(TEST_ADDRESS,)):
    return subject.ApprovedOrigin(TEST_HOST, 443, frozenset(addresses))


def response(data, content_type="application/json", status=200):
    return subject.Response(status, content_type, json.dumps({"data": data}).encode())


class MockTransport:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.calls = []

    def request(self, method, endpoint, headers):
        self.calls.append((method, endpoint, dict(headers)))
        return next(self.replies)


@contextlib.contextmanager
def raw_handle(path):
    handle = subject.RawDirectory(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    try:
        yield handle
    finally:
        handle.close()


class EndpointTests(unittest.TestCase):
    def test_exact_allowlist(self):
        self.assertEqual(subject.endpoint("nodes"), "/api2/json/nodes")
        self.assertEqual(subject.endpoint("lxc-list", "node1"), "/api2/json/nodes/node1/lxc")
        self.assertEqual(subject.endpoint("qemu-config", "node1", 121), "/api2/json/nodes/node1/qemu/121/config")
        self.assertEqual(subject.endpoint("lxc-status", "node1", "107"), "/api2/json/nodes/node1/lxc/107/status/current")

    def test_rejects_unknown_mutation_and_injection(self):
        for args in (
            ("delete", "node1", 107),
            ("lxc-config", "node1", "107?foo=bar"),
            ("lxc-list", "node1/../../access", None),
            ("nodes", "node1", None),
        ):
            with self.subTest(args=args), self.assertRaises(subject.InventoryError):
                subject.endpoint(*args)


class CollectionTests(unittest.TestCase):
    def test_collects_all_observed_ids_and_only_emits_counts(self):
        transport = MockTransport(
            [
                response([{"node": "node1"}]),
                response([{"vmid": 107}, {"vmid": 121}]),
                response({"memory": 512}), response({"status": "running"}),
                response({"memory": 256}), response({"status": "stopped"}),
                response([]),
            ]
        )
        with tempfile.TemporaryDirectory() as root:
            raw = Path(root) / "raw"
            raw.mkdir(mode=0o700)
            emitted = []
            with raw_handle(raw) as handle:
                subject.collect(transport, "audit@pve!phase0", "mock-value", handle, emitted.append)
            self.assertEqual(len(list(raw.glob("*.json"))), 7)
            for artifact in raw.glob("*.json"):
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertEqual(emitted, [
                "check_id=phase0-proxmox-nodes count=1",
                "check_id=phase0-proxmox-guests count=2",
                "check_id=phase0-proxmox-raw-artifacts count=7",
            ])
        self.assertTrue(all(call[0] == "GET" for call in transport.calls))
        self.assertTrue(all(call[1].startswith("/api2/json/nodes") for call in transport.calls))
        auth_values = [call[2]["Authorization"] for call in transport.calls]
        self.assertTrue(all(value == "PVEAPIToken=audit@pve!phase0=mock-value" for value in auth_values))
        self.assertNotIn("mock-value", "\n".join(emitted))

    def test_bad_response_leaves_no_partial_file(self):
        transport = MockTransport([subject.Response(200, "text/plain", b"not json")])
        with tempfile.TemporaryDirectory() as root:
            raw = Path(root) / "raw"
            raw.mkdir(mode=0o700)
            with raw_handle(raw) as handle, self.assertRaises(subject.InventoryError):
                subject.collect(transport, "mock-id", "mock-value", handle)
            self.assertEqual(list(raw.iterdir()), [])

    def test_mid_collection_failure_removes_completed_artifacts(self):
        transport = MockTransport([
            response([{"node": "node1"}]),
            response([{"vmid": 107}]),
            response({"memory": 512}),
            subject.Response(500, "application/json", b'{"data":null}'),
        ])
        with tempfile.TemporaryDirectory() as root:
            raw = Path(root) / "raw"
            raw.mkdir(mode=0o700)
            with raw_handle(raw) as handle, self.assertRaises(subject.InventoryError):
                subject.collect(transport, "mock-id", "mock-value", handle)
            self.assertEqual(list(raw.iterdir()), [])

    def test_existing_artifact_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            raw = Path(root)
            target = raw / "safe.json"
            target.write_text("old")
            with raw_handle(raw) as handle, self.assertRaises(subject.InventoryError):
                subject.write_new_json(handle, "safe.json", {"data": []})
            self.assertEqual(target.read_text(), "old")
            self.assertEqual(sorted(item.name for item in raw.iterdir()), ["safe.json"])

    def test_post_link_unlink_failure_removes_final_and_temporary(self):
        real_unlink = os.unlink
        failed = False

        def fail_first_temporary(name, *args, **kwargs):
            nonlocal failed
            if str(name).startswith(".phase0-") and not failed:
                failed = True
                raise OSError("injected unlink failure")
            return real_unlink(name, *args, **kwargs)

        with tempfile.TemporaryDirectory() as root:
            raw = Path(root)
            with raw_handle(raw) as handle, mock.patch.object(subject.os, "unlink", side_effect=fail_first_temporary):
                with self.assertRaises(subject.InventoryError):
                    subject.write_new_json(handle, "safe.json", {"data": []})
            self.assertEqual(list(raw.iterdir()), [])

    def test_post_link_fsync_failure_removes_final(self):
        real_fsync = os.fsync
        calls = 0

        def fail_directory_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory fsync failure")
            return real_fsync(fd)

        with tempfile.TemporaryDirectory() as root:
            raw = Path(root)
            with raw_handle(raw) as handle, mock.patch.object(subject.os, "fsync", side_effect=fail_directory_fsync):
                with self.assertRaises(subject.InventoryError):
                    subject.write_new_json(handle, "safe.json", {"data": []})
            self.assertEqual(list(raw.iterdir()), [])


class BoundaryTests(unittest.TestCase):
    def test_local_tofu_capture_connects_once_without_http_or_authorization(self):
        certificate = b"first-use-leaf-certificate"

        class FakeSocket:
            @staticmethod
            def getpeercert(binary_form=False):
                return certificate if binary_form else {}

            @staticmethod
            def getpeername():
                return TEST_ADDRESS, 443

        class CaptureConnection:
            instances = []

            def __init__(self, host, port, timeout, context):
                self.sock = FakeSocket()
                self.requests = []
                self.__class__.instances.append(self)

            def connect(self):
                return None

            def request(self, *args, **kwargs):
                self.requests.append((args, kwargs))

            def close(self):
                return None

        with mock.patch.object(subject.http.client, "HTTPSConnection", CaptureConnection):
            observed = subject.capture_local_tofu_fingerprint(approved_origin())
        self.assertEqual(observed, hashlib.sha256(certificate).hexdigest())
        self.assertEqual(len(CaptureConnection.instances), 1)
        self.assertEqual(CaptureConnection.instances[0].requests, [])

    def test_certificate_change_after_tofu_aborts_before_credential_request(self):
        first_certificate = b"first-use-leaf-certificate"
        changed_certificate = b"changed-leaf-certificate"

        class FakeSocket:
            def __init__(self, certificate):
                self.certificate = certificate

            def getpeercert(self, binary_form=False):
                return self.certificate if binary_form else {}

            @staticmethod
            def getpeername():
                return TEST_ADDRESS, 443

        class FakeConnection:
            certificates = iter((first_certificate, changed_certificate))
            instances = []

            def __init__(self, host, port, timeout, context):
                self.sock = FakeSocket(next(self.certificates))
                self.requests = []
                self.__class__.instances.append(self)

            def connect(self):
                return None

            def request(self, method, endpoint, headers):
                self.requests.append((method, endpoint, headers))

            def close(self):
                return None

        with mock.patch.object(subject.http.client, "HTTPSConnection", FakeConnection):
            origin = approved_origin()
            captured = subject.capture_local_tofu_fingerprint(origin)
            transport = subject.HTTPSPinnedTransport(origin, captured)
            with self.assertRaises(subject.InventoryError):
                transport.request(
                    "GET",
                    subject.endpoint("nodes"),
                    {"Authorization": "PVEAPIToken=mock-id=mock-value"},
                )
        self.assertEqual(len(FakeConnection.instances), 2)
        self.assertEqual(FakeConnection.instances[0].requests, [])
        self.assertEqual(FakeConnection.instances[1].requests, [])

    def test_self_signed_fallback_sends_credentials_only_after_exact_pin(self):
        certificate = b"self-signed-local-leaf"
        fingerprint = hashlib.sha256(certificate).hexdigest()

        class FakeSocket:
            @staticmethod
            def getpeercert(binary_form=False):
                return certificate if binary_form else {}

            @staticmethod
            def getpeername():
                return TEST_ADDRESS, 443

        class SystemTrustFailure:
            requests = []

            def __init__(self, *args, **kwargs):
                self.sock = None

            def connect(self):
                raise ssl.SSLCertVerificationError("synthetic untrusted issuer")

            def close(self):
                return None

        class PinConnection:
            requests = []

            def __init__(self, *args, **kwargs):
                self.sock = FakeSocket()

            def connect(self):
                return None

            def request(self, method, endpoint, headers):
                self.__class__.requests.append((method, endpoint, headers))

            def getresponse(self):
                return subject.Response(200, "application/json", b'{"data":[]}')

            def close(self):
                return None

        # Adapt the response object to the small http.client interface.
        response = mock.Mock(status=200)
        response.getheader.return_value = "application/json"
        response.read.return_value = b'{"data":[]}'
        PinConnection.getresponse = lambda self: response

        with mock.patch.object(
            subject.http.client,
            "HTTPSConnection",
            side_effect=(SystemTrustFailure(), PinConnection()),
        ):
            transport = subject.HTTPSPinnedTransport(approved_origin(), fingerprint)
            result = transport.request(
                "GET",
                subject.endpoint("nodes"),
                {"Authorization": "PVEAPIToken=mock-id=mock-value"},
            )
        self.assertEqual(result.status, 200)
        self.assertEqual(SystemTrustFailure.requests, [])
        self.assertEqual(len(PinConnection.requests), 1)

    def test_tofu_mode_captures_once_and_emits_only_sanitized_observation(self):
        fingerprint = "a" * 64

        class DummyRawDirectory:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

        stdout = io.StringIO()
        call_order = []

        def capture_without_loaded_token(origin):
            call_order.append("capture")
            return fingerprint

        def load_token_after_capture():
            call_order.append("token")
            return "mock-id", "mock-value"

        origin = approved_origin()
        with mock.patch.object(subject, "environment_host", return_value=f"https://{TEST_HOST}"), mock.patch.object(
            subject, "resolve_approved_origin", return_value=origin
        ), mock.patch.object(
            subject, "environment_token", side_effect=load_token_after_capture
        ), mock.patch.object(
            subject, "capture_local_tofu_fingerprint", side_effect=capture_without_loaded_token
        ) as capture, mock.patch.object(
            subject, "HTTPSPinnedTransport"
        ) as transport_type, mock.patch.object(
            subject, "open_raw_dir", return_value=DummyRawDirectory()
        ), mock.patch.object(subject, "collect") as collect, contextlib.redirect_stdout(stdout):
            result = subject.main(["--raw-dir", "/operator/approved", "--operator-approved-local-tofu"])
        self.assertEqual(result, 0)
        capture.assert_called_once_with(origin)
        self.assertEqual(call_order, ["capture", "token"])
        transport_type.assert_called_once_with(origin, fingerprint)
        collect.assert_called_once()
        output = stdout.getvalue()
        self.assertIn("status=observed", output)
        self.assertIn("residual_risk=not-independently-verified", output)
        self.assertIn(f"fingerprint_sha256={fingerprint}", output)
        self.assertIn(f"target_sha256={origin.opaque_target}", output)
        self.assertNotIn(TEST_HOST, output)
        self.assertNotIn("mock-id", output)
        self.assertNotIn("mock-value", output)

    def test_transport_directly_rejects_every_non_allowlisted_request(self):
        transport = subject.HTTPSPinnedTransport(approved_origin(), "0" * 64)
        cases = (
            ("POST", subject.endpoint("nodes")),
            ("GET", subject.endpoint("nodes") + "?full=1"),
            ("GET", subject.endpoint("nodes") + "#fragment"),
            ("GET", "/api2/json/access/users"),
            ("GET", "/api2/json/nodes/node1/lxc/107/status/start"),
        )
        with mock.patch.object(subject.http.client, "HTTPSConnection") as connection:
            for method, path in cases:
                with self.subTest(method=method, path=path), self.assertRaises(subject.InventoryError):
                    transport.request(method, path, {})
        connection.assert_not_called()

    def test_dns_rebinding_peer_is_rejected_before_credential_request(self):
        certificate = b"same-certificate-different-peer"

        class ReboundSocket:
            @staticmethod
            def getpeername():
                return "10.99.88.77", 443

            @staticmethod
            def getpeercert(binary_form=False):
                return certificate if binary_form else {}

        class ReboundConnection:
            requests = []

            def __init__(self, *args, **kwargs):
                self.sock = ReboundSocket()

            def connect(self):
                return None

            def request(self, *args, **kwargs):
                self.__class__.requests.append((args, kwargs))

            def close(self):
                return None

        with mock.patch.object(subject.http.client, "HTTPSConnection", ReboundConnection):
            transport = subject.HTTPSPinnedTransport(
                approved_origin(), hashlib.sha256(certificate).hexdigest()
            )
            with self.assertRaises(subject.InventoryError):
                transport.request(
                    "GET",
                    subject.endpoint("nodes"),
                    {"Authorization": "PVEAPIToken=mock-id=mock-value"},
                )
        self.assertEqual(ReboundConnection.requests, [])

    def test_https_transport_uses_system_context_and_checks_peer_pin(self):
        certificate = b"synthetic-peer-certificate"
        expected = hashlib.sha256(certificate).hexdigest()

        class FakeHTTPResponse:
            status = 200

            @staticmethod
            def getheader(name, default):
                return "application/json" if name == "Content-Type" else default

            @staticmethod
            def read(limit):
                return b'{"data":[]}'

        class FakeSocket:
            @staticmethod
            def getpeercert(binary_form=False):
                return certificate if binary_form else {}

            @staticmethod
            def getpeername():
                return TEST_ADDRESS, 443

        class FakeConnection:
            instances = []

            def __init__(self, host, port, timeout, context):
                self.host = host
                self.port = port
                self.timeout = timeout
                self.context = context
                self.sock = FakeSocket()
                self.requests = []
                self.__class__.instances.append(self)

            def connect(self):
                return None

            def request(self, method, endpoint, headers):
                self.requests.append((method, endpoint, headers))

            def getresponse(self):
                return FakeHTTPResponse()

            def close(self):
                return None

        system_context = object()
        with mock.patch.object(subject.ssl, "create_default_context", return_value=system_context) as context_factory, mock.patch.object(
            subject.http.client, "HTTPSConnection", FakeConnection
        ):
            transport = subject.HTTPSPinnedTransport(approved_origin(), expected)
            result = transport.request("GET", subject.endpoint("nodes"), {"Accept": "application/json"})
        context_factory.assert_called_once_with()
        self.assertEqual(result.status, 200)
        self.assertIs(FakeConnection.instances[0].context, system_context)
        self.assertEqual(len(FakeConnection.instances[0].requests), 1)

        FakeConnection.instances.clear()
        with mock.patch.object(subject.ssl, "create_default_context", return_value=system_context), mock.patch.object(
            subject.http.client, "HTTPSConnection", FakeConnection
        ):
            transport = subject.HTTPSPinnedTransport(approved_origin(), "0" * 64)
            with self.assertRaises(subject.InventoryError):
                transport.request("GET", subject.endpoint("nodes"), {})
        self.assertEqual(FakeConnection.instances[0].requests, [])

    def test_raw_directory_boundary_and_held_fd_defeat_substitution(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            worktree = base / "repo"
            worktree.mkdir()
            fake_tmp = base / "temp-root"
            fake_tmp.mkdir()
            inside = worktree / "raw"
            inside.mkdir(mode=0o700)
            with self.assertRaises(subject.InventoryError):
                subject.open_raw_dir(inside, worktree, fake_tmp)
            outside = base / "approved"
            outside.mkdir(mode=0o700)
            held = subject.open_raw_dir(outside, worktree, fake_tmp)
            original = base / "approved-original"
            outside.rename(original)
            outside.mkdir(mode=0o700)
            try:
                subject.write_new_json(held, "held.json", {"data": []})
            finally:
                held.close()
            self.assertTrue((original / "held.json").is_file())
            self.assertFalse((outside / "held.json").exists())
            outside.chmod(0o755)
            with self.assertRaises(subject.InventoryError):
                subject.open_raw_dir(outside, worktree, fake_tmp)

    def test_cwd_cannot_bypass_immutable_repository_boundary(self):
        old_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(dir=subject.REPOSITORY_ROOT) as root, tempfile.TemporaryDirectory() as elsewhere:
            raw = Path(root) / "raw"
            raw.mkdir(mode=0o700)
            try:
                os.chdir(elsewhere)
                with self.assertRaises(subject.InventoryError):
                    subject.open_raw_dir(raw)
            finally:
                os.chdir(old_cwd)

    def test_environment_reads_only_documented_credential_names(self):
        values = {
            "PROXMOX_HOST": "pve.invalid",
            "PROXMOX_TOKEN_ID": "mock-id",
            "PROXMOX_TOKEN_SECRET": "mock-value",
            "UNRELATED": "ignored",
        }
        with mock.patch.dict(os.environ, values, clear=True):
            self.assertEqual(subject.environment_host(), "pve.invalid")
            self.assertEqual(subject.environment_token(), ("mock-id", "mock-value"))

    def test_safe_error_does_not_include_environment_values(self):
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {
            "PROXMOX_HOST": "https://identity.invalid/path",
            "PROXMOX_TOKEN_ID": "mock-id",
            "PROXMOX_TOKEN_SECRET": "mock-value",
        }, clear=True), contextlib.redirect_stderr(stderr):
            result = subject.main(["--raw-dir", "/missing/private", "--tls-sha256", "0" * 64])
        self.assertEqual(result, 1)
        output = stderr.getvalue()
        self.assertNotIn("identity.invalid", output)
        self.assertNotIn("mock-id", output)
        self.assertNotIn("mock-value", output)

    def test_host_and_fingerprint_validation(self):
        self.assertEqual(subject.parse_host(f"https://{TEST_HOST}"), (TEST_HOST, 443))
        self.assertEqual(subject.parse_host(f"https://{TEST_HOST}:443/"), (TEST_HOST, 443))
        self.assertEqual(subject.normalize_fingerprint("SHA256:" + "A" * 64), "a" * 64)
        self.assertEqual(subject.normalize_fingerprint(":".join(["AA"] * 32)), "aa" * 32)
        for host in (
            f"http://{TEST_HOST}",
            f"https://user@{TEST_HOST}",
            f"https://{TEST_HOST}/api",
            f"https://{TEST_HOST}?x=1",
            f"https://{TEST_HOST}#fragment",
            f"https://{TEST_HOST}:8006",
            f"https://{TEST_HOST}:0",
            f"https://{TEST_HOST}:",
            TEST_HOST,
            "https://127.0.0.1",
            "https://10.0.0.1",
            "https://167772161",
            "https://0x0a000001",
            "https://012.0.0.1",
            "https://10.1",
            "https://0177.0.0.1",
            "https://0x7f000001",
            "https://2130706433",
            f"https://bad_host.{TEST_HOST}",
            f"https://{TEST_HOST}\n.invalid",
            f" https://{TEST_HOST}",
            f"https://{TEST_HOST} ",
            f"https://%70ve.{TEST_HOST}",
        ):
            with self.subTest(host=host), self.assertRaises(subject.InventoryError):
                subject.parse_host(host)

    def test_resolution_rejects_public_mixed_loopback_and_link_local_answers(self):
        def resolver_for(*addresses):
            return lambda host, port, type: [
                (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                for address in addresses
            ]

        accepted = subject.resolve_approved_origin(
            f"https://{TEST_HOST}", resolver_for("10.20.30.40", "10.42.0.10")
        )
        self.assertEqual(accepted.addresses, frozenset(("10.20.30.40", "10.42.0.10")))
        for addresses in (
            ("8.8.8.8",),
            ("10.20.30.40", "8.8.8.8"),
            ("127.0.0.1",),
            ("169.254.1.2",),
            ("::1",),
            ("fe80::1",),
        ):
            with self.subTest(addresses=addresses), self.assertRaises(subject.InventoryError):
                subject.resolve_approved_origin(f"https://{TEST_HOST}", resolver_for(*addresses))

    def test_legacy_numeric_host_is_rejected_before_dns_resolver(self):
        for numeric_host in ("167772161", "0x0a000001", "012.0.0.1"):
            resolver = mock.Mock()
            with self.subTest(numeric_host=numeric_host), self.assertRaises(subject.InventoryError):
                subject.resolve_approved_origin(f"https://{numeric_host}", resolver)
            resolver.assert_not_called()

    def test_response_schema_and_size(self):
        with self.assertRaises(subject.InventoryError):
            subject.decode_response(subject.Response(200, "application/json", b'{"data":[],"extra":1}'), list)
        with self.assertRaises(subject.InventoryError):
            subject.decode_response(subject.Response(200, "application/json", b"x" * (subject.MAX_RESPONSE_BYTES + 1)), list)

    def test_rejects_header_control_characters(self):
        transport = MockTransport([])
        with self.assertRaises(subject.InventoryError):
            subject.fetch(transport, "mock-id", "mock-value\nunsafe", subject.endpoint("nodes"), list)
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
